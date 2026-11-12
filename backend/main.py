"""
main.py — FastAPI application for CVEWatch.

Endpoints:
  GET  /api/cves              — paginated CVE list with filters
  GET  /api/cves/{cve_id}     — full detail for one CVE
  GET  /api/stats             — dashboard header stats
  POST /api/refresh           — trigger manual CVE fetch
  GET  /api/stream            — SSE stream for live updates
  GET  /api/android/status    — check ADB availability + connected devices
  POST /api/android/scan      — run full Android vulnerability scan
  GET  /api/android/history   — past scan summaries
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime

import aiosqlite
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from database import DB_PATH, init_db, get_cves, get_cve_detail, get_stats
from fetcher import run_fetch, INITIAL_DAYS_BACK
from android_scanner import (
    check_adb_available, list_devices, run_scan, get_scan_history
)

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s"
)
logger = logging.getLogger("cvewatch.main")

# SSE subscriber queues — one per connected dashboard client
_sse_clients: list[asyncio.Queue] = []

REFRESH_INTERVAL_MINUTES = int(os.getenv("REFRESH_INTERVAL_MINUTES", "30"))


async def _broadcast(event: dict):
    """Push an event to all connected SSE clients."""
    for q in _sse_clients:
        await q.put(event)


async def _scheduled_fetch():
    """Called by APScheduler every REFRESH_INTERVAL_MINUTES."""
    logger.info("Scheduled CVE refresh starting...")
    result = await run_fetch(days_back=1)
    await _broadcast({"type": "refresh", "data": result})
    logger.info(f"Scheduled refresh done: {result}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    logger.info("Database initialized.")

    # Check if DB is empty — if so, do a larger initial fetch
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM cves") as cur:
            count = (await cur.fetchone())[0]

    if count == 0:
        logger.info(f"Empty database — running initial fetch for last {INITIAL_DAYS_BACK} days...")
        result = await run_fetch(days_back=INITIAL_DAYS_BACK)
        await _broadcast({"type": "initial_fetch", "data": result})

    # Start background scheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        _scheduled_fetch,
        IntervalTrigger(minutes=REFRESH_INTERVAL_MINUTES),
        id="cve_refresh",
        replace_existing=True
    )
    scheduler.start()
    logger.info(f"Scheduler started — refreshing every {REFRESH_INTERVAL_MINUTES} minutes.")

    yield

    # Shutdown
    scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped.")


app = FastAPI(title="CVEWatch", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the frontend static files
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/static", StaticFiles(directory=frontend_path), name="static")


# ── Routes ──────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    """Serve the dashboard HTML."""
    return FileResponse(os.path.join(frontend_path, "index.html"))


@app.get("/api/stats")
async def stats():
    async with aiosqlite.connect(DB_PATH) as db:
        return await get_stats(db)


@app.get("/api/cves")
async def list_cves(
    severity: str = Query(default="ALL", description="CRITICAL|HIGH|MEDIUM|LOW|ALL"),
    search: str = Query(default=None, description="Search CVE ID, description, vendor, product"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    sort_by: str = Query(default="published", description="published|cvss_score|severity"),
    sort_order: str = Query(default="desc", description="asc|desc"),
):
    async with aiosqlite.connect(DB_PATH) as db:
        results = await get_cves(db, severity, search, limit, offset, sort_by, sort_order)
    return {"cves": results, "count": len(results), "offset": offset}


@app.get("/api/cves/{cve_id}")
async def cve_detail(cve_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        record = await get_cve_detail(db, cve_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    return record


@app.post("/api/refresh")
async def manual_refresh(days_back: int = Query(default=1, ge=1, le=90)):
    """Trigger a manual CVE fetch."""
    result = await run_fetch(days_back=days_back)
    await _broadcast({"type": "refresh", "data": result})
    return result


@app.get("/api/stream")
async def sse_stream():
    """
    Server-Sent Events endpoint.
    Dashboard connects here to receive live push notifications
    when new CVEs arrive or a refresh completes.
    """
    queue: asyncio.Queue = asyncio.Queue()
    _sse_clients.append(queue)

    async def event_generator():
        try:
            # Send a heartbeat immediately on connect
            yield "event: connected\ndata: {\"status\": \"live\"}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=25)
                    yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat every 25s
                    yield "event: heartbeat\ndata: {}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            _sse_clients.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# ── Android Scanner Routes ───────────────────────────────────────────────────

@app.get("/api/android/status")
async def android_status():
    """
    Check ADB availability and list connected devices.
    Call this when the user opens the Android tab to show device state.
    """
    adb = await check_adb_available()
    if not adb["available"]:
        return {"adb_available": False, "error": adb["error"], "devices": []}

    devices = await list_devices()
    return {
        "adb_available": True,
        "adb_version": adb.get("version", ""),
        "devices": devices,
        "online_count": sum(1 for d in devices if d["state"] == "device"),
    }


@app.post("/api/android/scan")
async def android_scan(serial: str = Query(default=None, description="Device serial (optional if only one connected)")):
    """
    Run a full Android vulnerability scan on the connected device.
    - Fingerprints the device via ADB
    - Lists installed packages
    - Matches against the CVE database
    - Returns full vulnerability report
    """
    logger.info(f"Android scan requested for serial={serial}")
    report = await run_scan(serial=serial)

    if report["status"] == "ok":
        # Broadcast scan completion to all SSE clients
        await _broadcast({
            "type": "android_scan_complete",
            "data": {
                "device": f"{report['device'].get('manufacturer', '')} {report['device'].get('model', '')}".strip(),
                "total_vulns": report["total_vulnerabilities"],
                "critical": report["severity_summary"].get("CRITICAL", 0),
            }
        })

    return report


@app.get("/api/android/history")
async def android_history():
    """Return past Android scan summaries."""
    history = await get_scan_history()
    return {"scans": history}
