# ⬡ CVEWatch

**Live CVE Intelligence Dashboard** — continuously fetches the latest vulnerabilities from NVD and CISA KEV, stores them locally, and shows them in a real-time dark-mode dashboard with full remediation details.

---

## Features

- **Live CVE feed** from NIST NVD API v2 — refreshes every 30 minutes automatically
- **CISA KEV enrichment** — flags actively exploited vulnerabilities
- **Full detail modal** per CVE: description, CVSS score, affected versions, CWE, references
- **Remediation steps** auto-generated per CVE (severity-aware + CWE-specific guidance)
- **Filters**: severity, sort order, search by keyword/vendor/product
- **Real-time push** via Server-Sent Events — table updates the moment new CVEs arrive
- **Local SQLite cache** — fast, offline-capable, no cloud dependency

---

## Quick Start

```powershell
# From the CVEWatch folder
.\start.ps1
```

Then open **http://localhost:8000** in your browser.

On first run it fetches the last 30 days of CVEs (~a few thousand). Subsequent refreshes are incremental (last 24 hours).

---

## Optional: NVD API Key

The NVD API works without a key but is rate-limited to 5 requests/30s.
With a free API key it increases to 50 requests/30s (much faster initial load).

1. Get a key at: https://nvd.nist.gov/developers/request-an-api-key
2. Add it to `.env`:
   ```
   NVD_API_KEY=your-key-here
   ```

---

## Project Structure

```
CVEWatch/
├── backend/
│   ├── main.py          # FastAPI app — API routes + SSE + scheduler
│   ├── database.py      # SQLite layer — schema, queries
│   ├── fetcher.py       # NVD + CISA KEV fetch + CVE normalization
│   └── requirements.txt
├── frontend/
│   ├── index.html       # Dashboard HTML
│   ├── style.css        # Dark-mode styles
│   └── app.js           # Dashboard logic (fetch, render, SSE, modal)
├── data/                # SQLite DB lives here (auto-created)
├── .env                 # Config (API key, refresh interval)
├── start.ps1            # One-command startup script
└── README.md
```

---

## Phase 2 (coming next)

Android device scanner — connect your Android phone via USB and assess it against the full CVE database to find vulnerabilities specific to your device's OS version, security patch level, and installed apps.
