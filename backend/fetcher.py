"""
fetcher.py — Pulls CVE data from NVD (NIST) and CISA KEV feeds.

Sources:
  1. NVD API v2  — full CVSS details, descriptions, references
  2. CISA KEV    — Known Exploited Vulnerabilities (high-priority subset)

No API key required for basic NVD usage (rate-limited to 5 req/30s).
Set NVD_API_KEY in .env to increase to 50 req/30s.
"""

import aiohttp
import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta

import aiosqlite
from database import DB_PATH, upsert_cve

logger = logging.getLogger("cvewatch.fetcher")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# How many days back to fetch on first run / incremental refresh
INITIAL_DAYS_BACK = 30
REFRESH_DAYS_BACK = 1  # for scheduled refreshes


def _build_remediation(cve_data: dict, cisa_kev_ids: set) -> str:
    """Generate a human-readable remediation string from CVE data."""
    lines = []
    cve_id = cve_data.get("cve_id", "")

    # CISA KEV flag
    if cve_id in cisa_kev_ids:
        lines.append("⚠️  ACTIVELY EXPLOITED — CISA Known Exploited Vulnerability. Patch immediately.")

    # Patch availability hint from references
    refs = cve_data.get("references", "")
    if any(kw in refs.lower() for kw in ["patch", "update", "fix", "advisory", "bulletin"]):
        lines.append("✅ Vendor patch/advisory available. Apply the latest update from the references below.")
        cve_data["patch_available"] = 1
    else:
        lines.append("🔍 No confirmed vendor patch detected. Apply workarounds and monitor vendor advisories.")

    severity = cve_data.get("severity", "")
    score = cve_data.get("cvss_score", 0) or 0

    if severity == "CRITICAL" or score >= 9.0:
        lines.append("🔴 CRITICAL: Isolate affected systems immediately. Restrict network access until patched.")
    elif severity == "HIGH" or score >= 7.0:
        lines.append("🟠 HIGH: Prioritize patching within 24–72 hours. Enable additional monitoring.")
    elif severity == "MEDIUM" or score >= 4.0:
        lines.append("🟡 MEDIUM: Schedule patching within your next maintenance window.")
    else:
        lines.append("🟢 LOW: Address during routine maintenance cycle.")

    # CWE-specific guidance
    cwe = cve_data.get("cwe", "")
    cwe_guidance = {
        "CWE-79":  "Sanitize all user inputs. Implement Content Security Policy (CSP).",
        "CWE-89":  "Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
        "CWE-787": "Update to patched version. Enable memory-safe compiler flags where possible.",
        "CWE-125": "Update to patched version. Enable bounds checking.",
        "CWE-416": "Update to patched version. Use memory-safe languages for new components.",
        "CWE-20":  "Validate and sanitize all external inputs.",
        "CWE-22":  "Validate file paths. Use allow-lists for accessible directories.",
        "CWE-352": "Implement CSRF tokens on all state-changing requests.",
        "CWE-306": "Enforce authentication on all sensitive endpoints.",
        "CWE-502": "Avoid deserializing untrusted data. Use allow-lists for class deserialization.",
    }
    if cwe and cwe in cwe_guidance:
        lines.append(f"💡 {cwe} Guidance: {cwe_guidance[cwe]}")

    return " | ".join(lines) if lines else "Review vendor advisory and apply available patches."


def _parse_nvd_item(item: dict, cisa_kev_ids: set) -> dict:
    """Parse a single NVD CVE item into our normalized schema."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    # Description (English preferred)
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "No description available."
    )

    # CVSS scores — prefer v3.1, fall back to v3.0, then v2
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_vector = ""
    severity = "UNKNOWN"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString", "")
            severity = m.get("baseSeverity") or metrics[key][0].get("baseSeverity", "UNKNOWN")
            break

    # Normalize severity
    if cvss_score is not None and severity == "UNKNOWN":
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # CWE
    weaknesses = cve.get("weaknesses", [])
    cwe = ""
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                cwe = desc["value"]
                break
        if cwe:
            break

    # References
    refs_raw = cve.get("references", [])
    refs = " | ".join(r.get("url", "") for r in refs_raw[:8])  # cap at 8

    # Vendor / product from CPE configurations
    vendor = ""
    product = ""
    affected_versions = ""
    configs = cve.get("configurations", [])
    if configs:
        nodes = configs[0].get("nodes", [])
        if nodes:
            cpe_matches = nodes[0].get("cpeMatch", [])
            if cpe_matches:
                cpe = cpe_matches[0].get("criteria", "")
                parts = cpe.split(":")
                if len(parts) > 4:
                    vendor = parts[3]
                    product = parts[4]
                versions = []
                for cm in cpe_matches[:5]:
                    start = cm.get("versionStartIncluding") or cm.get("versionStartExcluding")
                    end = cm.get("versionEndIncluding") or cm.get("versionEndExcluding")
                    if start and end:
                        versions.append(f"{start}–{end}")
                    elif end:
                        versions.append(f"up to {end}")
                    elif start:
                        versions.append(f">= {start}")
                affected_versions = ", ".join(versions)

    record = {
        "cve_id": cve_id,
        "published": published,
        "modified": modified,
        "severity": severity.upper(),
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "description": description,
        "references": refs,
        "cwe": cwe,
        "vendor": vendor,
        "product": product,
        "affected_versions": affected_versions,
        "patch_available": 0,
        "source": "NVD",
        "remediation": "",  # filled below
    }
    record["remediation"] = _build_remediation(record, cisa_kev_ids)
    return record


async def fetch_cisa_kev(session: aiohttp.ClientSession) -> set:
    """Returns a set of CVE IDs that are in CISA's Known Exploited Vulnerabilities list."""
    try:
        async with session.get(CISA_KEV_URL, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        logger.warning(f"CISA KEV fetch failed: {e}")
    return set()


async def fetch_nvd_page(
    session: aiohttp.ClientSession,
    start_index: int,
    pub_start: str,
    pub_end: str,
    api_key: str = None
) -> dict:
    """Fetch one page of NVD results."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": 100,
        "startIndex": start_index,
    }

    delay = 0.6 if api_key else 6.5  # respect NVD rate limits
    await asyncio.sleep(delay)

    async with session.get(
        NVD_BASE, params=params, headers=headers,
        timeout=aiohttp.ClientTimeout(total=60)
    ) as resp:
        resp.raise_for_status()
        return await resp.json()


async def run_fetch(days_back: int = None) -> dict:
    """
    Main fetch routine. Pulls CVEs from NVD for the last `days_back` days
    and upserts into the local SQLite database.
    Returns a summary dict.
    """
    api_key = os.getenv("NVD_API_KEY", "")
    if days_back is None:
        days_back = REFRESH_DAYS_BACK

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)

    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    logger.info(f"Fetching CVEs from {pub_start} to {pub_end}")

    new_count = 0
    updated_count = 0
    status = "ok"

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # First get CISA KEV list for enrichment
        cisa_kev_ids = await fetch_cisa_kev(session)
        logger.info(f"CISA KEV loaded: {len(cisa_kev_ids)} entries")

        try:
            # Initial request to get total count
            first_page = await fetch_nvd_page(session, 0, pub_start, pub_end, api_key)
            total = first_page.get("totalResults", 0)
            logger.info(f"Total CVEs to fetch: {total}")

            all_items = first_page.get("vulnerabilities", [])

            # Paginate through remaining results
            start_index = 100
            while start_index < total:
                page = await fetch_nvd_page(session, start_index, pub_start, pub_end, api_key)
                all_items.extend(page.get("vulnerabilities", []))
                start_index += 100

            # Upsert into DB
            async with aiosqlite.connect(DB_PATH) as db:
                for item in all_items:
                    record = _parse_nvd_item(item, cisa_kev_ids)
                    result = await upsert_cve(db, record)
                    if result == "new":
                        new_count += 1
                    elif result == "updated":
                        updated_count += 1
                await db.commit()

            logger.info(f"Fetch complete: {new_count} new, {updated_count} updated")

        except Exception as e:
            logger.error(f"NVD fetch error: {e}")
            status = f"error: {e}"

    # Log this run
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO fetch_log (fetched_at, source, new_count, updated_count, status) VALUES (?,?,?,?,?)",
            (now.isoformat(), "NVD+CISA", new_count, updated_count, status)
        )
        await db.commit()

    return {"new": new_count, "updated": updated_count, "status": status, "fetched_at": now.isoformat()}
