"""
android_scanner.py — Android USB device scanner for CVEWatch.

Uses ADB (Android Debug Bridge) over USB to:
  1. Detect connected Android devices
  2. Fingerprint the device (Android version, security patch date, build info)
  3. List all installed packages + versions
  4. Match fingerprint + packages against the local CVE database
  5. Return a structured vulnerability report with remediations

Prerequisites on the host machine:
  - ADB installed and in PATH  (Android Platform Tools)
  - USB debugging enabled on the Android device
  - Device trusted (RSA key accepted on first connect)
"""

import asyncio
import logging
import re
import subprocess
from datetime import datetime, timezone

import aiosqlite
from database import DB_PATH

logger = logging.getLogger("cvewatch.android")


# ── ADB helpers ──────────────────────────────────────────────────────────────

def _run_adb(*args, serial: str = None, timeout: int = 15) -> tuple[int, str, str]:
    """
    Run an adb command synchronously.
    Returns (returncode, stdout, stderr).
    """
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return -1, "", "adb not found — install Android Platform Tools and add to PATH"
    except subprocess.TimeoutExpired:
        return -2, "", f"adb command timed out after {timeout}s"
    except Exception as e:
        return -3, "", str(e)


async def check_adb_available() -> dict:
    """Check whether ADB is installed and returns its version."""
    loop = asyncio.get_event_loop()
    code, out, err = await loop.run_in_executor(None, lambda: _run_adb("version"))
    if code != 0:
        return {"available": False, "error": err or "ADB not found"}
    version_line = out.splitlines()[0] if out else "unknown"
    return {"available": True, "version": version_line}


async def list_devices() -> list[dict]:
    """
    Returns all currently connected ADB devices.
    Each dict has: serial, state, model (if available).
    """
    loop = asyncio.get_event_loop()
    code, out, err = await loop.run_in_executor(None, lambda: _run_adb("devices", "-l"))
    if code != 0:
        return []

    devices = []
    for line in out.splitlines()[1:]:  # skip "List of devices attached" header
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial = parts[0]
        state  = parts[1]
        # Parse model from key=value pairs if present
        model = ""
        for part in parts[2:]:
            if part.startswith("model:"):
                model = part.split(":", 1)[1].replace("_", " ")
        devices.append({"serial": serial, "state": state, "model": model})

    return devices


async def get_device_info(serial: str) -> dict:
    """
    Reads all relevant device properties via adb shell getprop.
    Returns a normalized device fingerprint dict.
    """
    loop = asyncio.get_event_loop()

    props_to_fetch = {
        "android_version":  "ro.build.version.release",
        "sdk_version":      "ro.build.version.sdk",
        "security_patch":   "ro.build.version.security_patch",
        "build_id":         "ro.build.id",
        "build_type":       "ro.build.type",
        "manufacturer":     "ro.product.manufacturer",
        "model":            "ro.product.model",
        "device":           "ro.product.device",
        "brand":            "ro.product.brand",
        "cpu_abi":          "ro.product.cpu.abi",
        "fingerprint":      "ro.build.fingerprint",
        "kernel_version":   "ro.kernel.version",
    }

    info = {"serial": serial}
    for key, prop in props_to_fetch.items():
        code, out, _ = await loop.run_in_executor(
            None, lambda p=prop: _run_adb("shell", "getprop", p, serial=serial)
        )
        info[key] = out if code == 0 else ""

    return info


async def get_installed_packages(serial: str) -> list[dict]:
    """
    Lists all installed packages with their version names.
    Returns list of {package_name, version}.
    """
    loop = asyncio.get_event_loop()

    # Get package names
    code, out, _ = await loop.run_in_executor(
        None, lambda: _run_adb("shell", "pm", "list", "packages", serial=serial, timeout=30)
    )
    if code != 0 or not out:
        return []

    packages = []
    for line in out.splitlines():
        # Format: "package:com.example.app"
        if line.startswith("package:"):
            pkg_name = line[8:].strip()
            packages.append(pkg_name)

    # Get versions via dumpsys for each package (batch via single shell call for speed)
    # Use awk to extract versionName for all packages in one call
    code2, out2, _ = await loop.run_in_executor(
        None, lambda: _run_adb(
            "shell",
            "dumpsys package | grep -E 'Package \\[|versionName'",
            serial=serial,
            timeout=60
        )
    )

    # Parse package → version map
    version_map = {}
    current_pkg = None
    for line in out2.splitlines():
        line = line.strip()
        pkg_match = re.match(r"Package \[(.+?)\]", line)
        ver_match  = re.match(r"versionName=(.+)", line)
        if pkg_match:
            current_pkg = pkg_match.group(1)
        elif ver_match and current_pkg:
            version_map[current_pkg] = ver_match.group(1)
            current_pkg = None

    return [
        {"package_name": p, "version": version_map.get(p, "unknown")}
        for p in packages
    ]


# ── CVE Matching ─────────────────────────────────────────────────────────────

def _parse_android_version(version_str: str) -> tuple[int, int]:
    """Parse '13', '13.0', '13.0.1' into (major, minor)."""
    parts = version_str.strip().split(".")
    try:
        major = int(parts[0]) if parts else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        return major, minor
    except (ValueError, IndexError):
        return 0, 0


def _parse_security_patch(patch_str: str) -> datetime | None:
    """Parse '2024-10-01' security patch date."""
    try:
        return datetime.strptime(patch_str.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


async def match_android_cves(device_info: dict, packages: list[dict]) -> list[dict]:
    """
    Query the CVE database for vulnerabilities relevant to this Android device.

    Matching strategy:
      1. Android OS CVEs — vendor='google', product='android', published after security patch date
      2. Kernel CVEs     — vendor='linux', product='linux_kernel'
      3. Package CVEs    — match installed package names against product column
      4. Manufacturer CVEs — match device manufacturer
    """
    android_version   = device_info.get("android_version", "")
    security_patch    = device_info.get("security_patch", "")
    manufacturer      = device_info.get("manufacturer", "").lower()

    patch_date = _parse_security_patch(security_patch)
    patch_date_str = patch_date.strftime("%Y-%m-%d") if patch_date else "1970-01-01"

    # Build a set of package name fragments for matching (lowercase)
    pkg_names = {p["package_name"].lower() for p in packages}
    # Extract simple app name from reverse-domain: com.google.android.apps.maps → maps, android
    pkg_fragments = set()
    for p in pkg_names:
        parts = p.split(".")
        pkg_fragments.update(parts)
    # Remove very generic fragments
    pkg_fragments -= {"com", "org", "net", "app", "apps", "android", "google",
                      "samsung", "huawei", "xiaomi", "1", "2", "3"}

    matched_cves = []

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # ── 1. Android OS CVEs ────────────────────────────────────────────
        async with db.execute("""
            SELECT * FROM cves
            WHERE (
                (vendor LIKE '%google%' AND product LIKE '%android%')
                OR description LIKE '%android%'
            )
            AND published > ?
            ORDER BY cvss_score DESC NULLS LAST, published DESC
            LIMIT 200
        """, (patch_date_str,)) as cur:
            rows = await cur.fetchall()
            for row in rows:
                cve = dict(row)
                cve["match_reason"] = "Android OS — published after your security patch date"
                cve["match_category"] = "os"
                matched_cves.append(cve)

        # ── 2. Linux Kernel CVEs ──────────────────────────────────────────
        async with db.execute("""
            SELECT * FROM cves
            WHERE vendor LIKE '%linux%'
            AND (product LIKE '%linux_kernel%' OR product LIKE '%kernel%')
            AND published > ?
            ORDER BY cvss_score DESC NULLS LAST, published DESC
            LIMIT 50
        """, (patch_date_str,)) as cur:
            rows = await cur.fetchall()
            seen = {c["cve_id"] for c in matched_cves}
            for row in rows:
                cve = dict(row)
                if cve["cve_id"] not in seen:
                    cve["match_reason"] = "Linux kernel — affects Android's underlying kernel"
                    cve["match_category"] = "kernel"
                    matched_cves.append(cve)
                    seen.add(cve["cve_id"])

        # ── 3. Manufacturer CVEs ──────────────────────────────────────────
        if manufacturer:
            async with db.execute("""
                SELECT * FROM cves
                WHERE vendor LIKE ?
                AND published > ?
                ORDER BY cvss_score DESC NULLS LAST, published DESC
                LIMIT 50
            """, (f"%{manufacturer}%", patch_date_str)) as cur:
                rows = await cur.fetchall()
                seen = {c["cve_id"] for c in matched_cves}
                for row in rows:
                    cve = dict(row)
                    if cve["cve_id"] not in seen:
                        cve["match_reason"] = f"Device manufacturer ({manufacturer}) specific vulnerability"
                        cve["match_category"] = "manufacturer"
                        matched_cves.append(cve)
                        seen.add(cve["cve_id"])

        # ── 4. Installed Package CVEs ─────────────────────────────────────
        # Match top-level package fragments against product column
        seen = {c["cve_id"] for c in matched_cves}
        for fragment in list(pkg_fragments)[:40]:  # cap to avoid too many queries
            if len(fragment) < 4:  # skip too-short fragments
                continue
            async with db.execute("""
                SELECT * FROM cves
                WHERE product LIKE ?
                ORDER BY cvss_score DESC NULLS LAST
                LIMIT 10
            """, (f"%{fragment}%",)) as cur:
                rows = await cur.fetchall()
                for row in rows:
                    cve = dict(row)
                    if cve["cve_id"] not in seen:
                        cve["match_reason"] = f"Installed package match: '{fragment}'"
                        cve["match_category"] = "package"
                        matched_cves.append(cve)
                        seen.add(cve["cve_id"])

    # Sort final results: CRITICAL first, then by CVSS score
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    matched_cves.sort(key=lambda c: (
        severity_order.get(c.get("severity", "UNKNOWN"), 4),
        -(c.get("cvss_score") or 0)
    ))

    return matched_cves


# ── Scan orchestrator ─────────────────────────────────────────────────────────

async def run_scan(serial: str = None) -> dict:
    """
    Full scan pipeline:
      1. Find device (auto-select if only one connected)
      2. Get device info
      3. Get installed packages
      4. Match CVEs
      5. Return structured report

    Returns a scan report dict.
    """
    # Detect devices
    devices = await list_devices()
    online   = [d for d in devices if d["state"] == "device"]

    if not online:
        return {
            "status": "error",
            "error": "No Android device detected. Make sure USB debugging is enabled and the device is trusted.",
            "devices_found": devices
        }

    # Pick device
    if serial:
        target = next((d for d in online if d["serial"] == serial), None)
        if not target:
            return {"status": "error", "error": f"Device {serial} not found or not online"}
    else:
        if len(online) > 1:
            return {
                "status": "multiple_devices",
                "error": "Multiple devices connected. Specify a serial.",
                "devices": online
            }
        target = online[0]

    logger.info(f"Scanning device: {target['serial']}")

    # Fingerprint
    device_info = await get_device_info(target["serial"])
    logger.info(f"Device: {device_info.get('manufacturer')} {device_info.get('model')} "
                f"Android {device_info.get('android_version')} patch {device_info.get('security_patch')}")

    # Installed packages
    logger.info("Fetching installed packages...")
    packages = await get_installed_packages(target["serial"])
    logger.info(f"Found {len(packages)} installed packages")

    # CVE matching
    logger.info("Matching CVEs...")
    cves = await match_android_cves(device_info, packages)
    logger.info(f"Found {len(cves)} relevant CVEs")

    # Build summary
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for cve in cves:
        s = cve.get("severity", "UNKNOWN")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    scan_time = datetime.now(timezone.utc).isoformat()

    report = {
        "status": "ok",
        "scan_time": scan_time,
        "device": device_info,
        "packages_scanned": len(packages),
        "total_vulnerabilities": len(cves),
        "severity_summary": severity_counts,
        "vulnerabilities": cves,
    }

    # Persist to DB
    await _save_scan(report)

    return report


async def _save_scan(report: dict):
    """Persist a scan report to the android_scans table."""
    import json
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS android_scans (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time        TEXT,
                serial           TEXT,
                manufacturer     TEXT,
                model            TEXT,
                android_version  TEXT,
                security_patch   TEXT,
                packages_scanned INTEGER,
                total_vulns      INTEGER,
                critical_count   INTEGER,
                high_count       INTEGER,
                medium_count     INTEGER,
                low_count        INTEGER,
                report_json      TEXT
            )
        """)
        import json as _json
        await db.execute("""
            INSERT INTO android_scans
                (scan_time, serial, manufacturer, model, android_version,
                 security_patch, packages_scanned, total_vulns,
                 critical_count, high_count, medium_count, low_count, report_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            report["scan_time"],
            report["device"].get("serial", ""),
            report["device"].get("manufacturer", ""),
            report["device"].get("model", ""),
            report["device"].get("android_version", ""),
            report["device"].get("security_patch", ""),
            report["packages_scanned"],
            report["total_vulnerabilities"],
            report["severity_summary"].get("CRITICAL", 0),
            report["severity_summary"].get("HIGH", 0),
            report["severity_summary"].get("MEDIUM", 0),
            report["severity_summary"].get("LOW", 0),
            _json.dumps({
                "device": report["device"],
                "severity_summary": report["severity_summary"],
                "packages_scanned": report["packages_scanned"],
            })
        ))
        await db.commit()


async def get_scan_history() -> list[dict]:
    """Return past scan summaries (without full vuln list)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS android_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT, serial TEXT, manufacturer TEXT,
                model TEXT, android_version TEXT, security_patch TEXT,
                packages_scanned INTEGER, total_vulns INTEGER,
                critical_count INTEGER, high_count INTEGER,
                medium_count INTEGER, low_count INTEGER, report_json TEXT
            )
        """)
        async with db.execute("""
            SELECT id, scan_time, manufacturer, model, android_version,
                   security_patch, packages_scanned, total_vulns,
                   critical_count, high_count, medium_count, low_count
            FROM android_scans ORDER BY id DESC LIMIT 20
        """) as cur:
            rows = await cur.fetchall()
            columns = [d[0] for d in cur.description]
            return [dict(zip(columns, row)) for row in rows]
