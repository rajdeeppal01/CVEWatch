"""
database.py — SQLite persistence layer for CVEWatch.
Stores fetched CVEs and tracks last-seen timestamps for deduplication.
"""

import aiosqlite
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cvewatch.db")


async def init_db():
    """Create tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id      TEXT PRIMARY KEY,
                published   TEXT,
                modified    TEXT,
                severity    TEXT,
                cvss_score  REAL,
                cvss_vector TEXT,
                description TEXT,
                "references" TEXT,
                remediation TEXT,
                cwe         TEXT,
                vendor      TEXT,
                product     TEXT,
                affected_versions TEXT,
                patch_available INTEGER DEFAULT 0,
                source      TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS fetch_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fetched_at  TEXT,
                source      TEXT,
                new_count   INTEGER,
                updated_count INTEGER,
                status      TEXT
            )
        """)
        await db.commit()


async def upsert_cve(db, cve: dict):
    """Insert or update a CVE record. Returns 'new' or 'updated'."""
    async with db.execute("SELECT modified FROM cves WHERE cve_id = ?", (cve["cve_id"],)) as cur:
        row = await cur.fetchone()

    if row is None:
        await db.execute("""
            INSERT INTO cves
                (cve_id, published, modified, severity, cvss_score, cvss_vector,
                 description, "references", remediation, cwe, vendor, product,
                 affected_versions, patch_available, source)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            cve["cve_id"], cve["published"], cve["modified"],
            cve["severity"], cve["cvss_score"], cve["cvss_vector"],
            cve["description"], cve["references"], cve["remediation"],
            cve["cwe"], cve["vendor"], cve["product"],
            cve["affected_versions"], cve["patch_available"], cve["source"]
        ))
        return "new"
    elif row[0] != cve["modified"]:
        await db.execute("""
            UPDATE cves SET
                modified=?, severity=?, cvss_score=?, cvss_vector=?,
                description=?, references=?, remediation=?, cwe=?,
                vendor=?, product=?, affected_versions=?, patch_available=?, source=?
            WHERE cve_id=?
        """, (
            cve["modified"], cve["severity"], cve["cvss_score"], cve["cvss_vector"],
            cve["description"], cve["references"], cve["remediation"], cve["cwe"],
            cve["vendor"], cve["product"], cve["affected_versions"],
            cve["patch_available"], cve["source"], cve["cve_id"]
        ))
        return "updated"
    return "unchanged"


async def get_cves(
    db,
    severity: str = None,
    search: str = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str = "published",
    sort_order: str = "desc"
):
    """Query CVEs with optional filters."""
    allowed_sort = {"published", "modified", "cvss_score", "severity"}
    if sort_by not in allowed_sort:
        sort_by = "published"
    sort_order = "DESC" if sort_order.lower() == "desc" else "ASC"

    conditions = []
    params = []

    if severity and severity.upper() != "ALL":
        conditions.append("severity = ?")
        params.append(severity.upper())

    if search:
        conditions.append("(cve_id LIKE ? OR description LIKE ? OR product LIKE ? OR vendor LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like, like])

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT cve_id, published, modified, severity, cvss_score,
               description, remediation, cwe, vendor, product,
               affected_versions, patch_available, source
        FROM cves
        {where}
        ORDER BY {sort_by} {sort_order}
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    async with db.execute(query, params) as cur:
        rows = await cur.fetchall()
        columns = [d[0] for d in cur.description]
        return [dict(zip(columns, row)) for row in rows]


async def get_cve_detail(db, cve_id: str):
    """Get full detail for a single CVE."""
    async with db.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)) as cur:
        row = await cur.fetchone()
        if row:
            columns = [d[0] for d in cur.description]
            return dict(zip(columns, row))
        return None


async def get_stats(db):
    """Return aggregate stats for the dashboard header."""
    stats = {}
    async with db.execute("SELECT COUNT(*) FROM cves") as cur:
        stats["total"] = (await cur.fetchone())[0]
    async with db.execute("SELECT COUNT(*) FROM cves WHERE severity='CRITICAL'") as cur:
        stats["critical"] = (await cur.fetchone())[0]
    async with db.execute("SELECT COUNT(*) FROM cves WHERE severity='HIGH'") as cur:
        stats["high"] = (await cur.fetchone())[0]
    async with db.execute("SELECT COUNT(*) FROM cves WHERE severity='MEDIUM'") as cur:
        stats["medium"] = (await cur.fetchone())[0]
    async with db.execute("SELECT COUNT(*) FROM cves WHERE severity='LOW'") as cur:
        stats["low"] = (await cur.fetchone())[0]
    async with db.execute("SELECT COUNT(*) FROM cves WHERE patch_available=1") as cur:
        stats["patched"] = (await cur.fetchone())[0]
    async with db.execute(
        "SELECT fetched_at, new_count, updated_count, status FROM fetch_log ORDER BY id DESC LIMIT 1"
    ) as cur:
        row = await cur.fetchone()
        if row:
            stats["last_fetch"] = {"at": row[0], "new": row[1], "updated": row[2], "status": row[3]}
        else:
            stats["last_fetch"] = None
    return stats
