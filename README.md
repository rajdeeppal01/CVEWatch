# ⬡ CVEWatch

**Live CVE Intelligence Dashboard with Android USB Scanner**

Continuously fetches the latest vulnerabilities from NIST NVD and CISA KEV, stores them locally in SQLite, and displays them in a real-time dark-mode dashboard. Connect any Android phone via USB to instantly assess it against the full CVE database and get device-specific remediation steps.

---

## Features

### CVE Feed
- Live CVE feed from **NIST NVD API v2** — auto-refreshes every 30 minutes
- **CISA KEV enrichment** — flags CVEs that are actively exploited in the wild
- **Auto-generated remediation steps** per CVE — severity-aware + CWE-specific guidance
- Filter by severity (Critical / High / Medium / Low / Pending), sort by date or CVSS score
- Full-text search by CVE ID, vendor, product, or keyword
- **Server-Sent Events** — table updates live the moment new CVEs arrive, no page refresh needed
- Full detail modal per CVE: description, CVSS score + vector, affected versions, CWE, references, patch status
- Local SQLite cache — fast, works offline after initial fetch

### Android Scanner
- **USB-based device fingerprinting** via ADB — reads Android version, security patch date, build info, manufacturer, CPU
- **CVE matching** across 4 categories:
  - 🤖 Android OS CVEs — published after your device's security patch date
  - 🐧 Linux kernel CVEs — affects the kernel underlying Android
  - 🏭 Manufacturer-specific CVEs — Samsung, Xiaomi, etc.
  - 📦 Installed app CVEs — matches your installed packages against known vulnerable products
- Severity summary report per scan (Critical / High / Medium / Low / Total)
- Full remediation steps for every vulnerability found
- Scan history — every past scan saved and accessible

---

## Project Structure

```
CVEWatch/
├── backend/
│   ├── main.py             # FastAPI app — all API routes, SSE stream, APScheduler
│   ├── database.py         # SQLite schema + all query functions
│   ├── fetcher.py          # NVD + CISA KEV fetch pipeline + CVE normalization
│   ├── android_scanner.py  # ADB bridge, device fingerprint, CVE matcher, scan history
│   └── requirements.txt    # Python dependencies
├── frontend/
│   ├── index.html          # Single-page dashboard — CVE Feed + Android Scanner tabs
│   ├── style.css           # Dark-mode design system (CSS variables, all components)
│   └── app.js              # All dashboard logic — fetch, render, SSE, modal, Android UI
├── data/                   # SQLite database lives here (auto-created on first run)
├── .env                    # Configuration (NVD API key, refresh interval)
├── start.ps1               # One-command startup script (Windows PowerShell)
└── README.md
```

---

## Requirements

- **Python 3.11+**
- **Windows** (PowerShell) — Linux/macOS can run `uvicorn backend/main:app` directly
- **ADB (Android Platform Tools)** — only needed for Android scanning
- Internet connection for the initial CVE fetch

---

## Part 1 — First Time Setup

### Step 1 — Clone the repo

```powershell
git clone https://github.com/rajdeeppal01/CVEWatch.git
cd CVEWatch
```

### Step 2 — Get a free NVD API key (recommended)

Without a key the initial fetch is rate-limited and slow (5 req/30s).
With a free key it runs at 50 req/30s — about 10x faster.

1. Go to: https://nvd.nist.gov/developers/request-an-api-key
2. Fill in your email, receive the key by email
3. Open `.env` in the project root and add it:

```
NVD_API_KEY=your-key-here
REFRESH_INTERVAL_MINUTES=30
```

### Step 3 — Run the start script

```powershell
.\start.ps1
```

This will:
1. Create a Python virtual environment (`.venv/`)
2. Install all dependencies automatically
3. Start the server on `http://localhost:8000`
4. Run the initial CVE fetch (last 30 days — ~15,000–20,000 CVEs)

> First run takes **2–5 minutes** depending on your connection and whether you have an API key.
> Every subsequent run starts in seconds — data is cached locally in SQLite.

### Step 4 — Open the dashboard

Go to **http://localhost:8000** in your browser.

Keep the PowerShell window open — closing it stops the server.

---

## Part 2 — Using the CVE Feed

The default tab shows the live CVE feed. The stats bar at the top always shows totals across all severities.

| Feature | How to use |
|---|---|
| Filter by severity | Use the **Severity** dropdown — Critical, High, Medium, Low, Pending |
| Sort | **Sort By** dropdown — Published Date or CVSS Score |
| Search | Type any CVE ID, vendor name, product name, or keyword |
| Change page size | **Per Page** dropdown — 25, 50, or 100 |
| View full details | Click any row or the **Details** button |
| Manual refresh | **↻ Refresh CVEs** button in the top-right corner |

### Detail Modal

Click any CVE to open a full detail panel showing:
- Complete description
- CVSS score and attack vector string
- Vendor, product, affected version ranges
- CWE weakness type
- **Remediation steps** — specific, actionable guidance based on severity and vulnerability type
- Official reference links

### Auto-refresh

CVEs refresh automatically every 30 minutes in the background (configurable in `.env`).
The **LIVE** indicator in the top bar confirms the SSE connection is active.
New CVEs push to the table instantly with no page reload.

### Severity Levels

| Badge | Meaning |
|---|---|
| 🔴 CRITICAL | CVSS 9.0–10.0 — Isolate affected systems immediately |
| 🟠 HIGH | CVSS 7.0–8.9 — Patch within 24–72 hours |
| 🟡 MEDIUM | CVSS 4.0–6.9 — Patch in next maintenance window |
| 🟢 LOW | CVSS 0.1–3.9 — Routine maintenance cycle |
| ⬜ PENDING | No CVSS score yet — NVD analysis in progress (newly published) |

---

## Part 3 — Android Scanner Setup (one-time)

### Step 1 — Install Android Platform Tools (ADB)

1. Download from: https://developer.android.com/tools/releases/platform-tools
2. Click **"Download SDK Platform-Tools for Windows"**
3. Extract the zip — you'll get a folder called `platform-tools` containing `adb.exe`
4. Move the folder to a permanent location, e.g. `C:\platform-tools\`

> **Note:** The zip often extracts as `platform-tools\platform-tools\` — make sure you point PATH to the folder that actually contains `adb.exe`.

### Step 2 — Add ADB to system PATH

1. Press `Win + S` → search **"Environment Variables"** → click **"Edit the system environment variables"**
2. Click **"Environment Variables..."**
3. Under **System variables** → find **Path** → click **Edit**
4. Click **New** → paste the path to your folder containing `adb.exe` (e.g. `C:\platform-tools\platform-tools`)
5. Click OK → OK → OK

### Step 3 — Verify ADB works

Open a **new** PowerShell window (existing ones won't see the new PATH) and run:

```powershell
adb version
```

Expected output:
```
Android Debug Bridge version 1.0.41
Version 35.x.x
```

### Step 4 — Enable Developer Options on your phone

1. Go to **Settings → About Phone**
2. Find **Build Number**
3. Tap **Build Number 7 times rapidly**
4. You'll see: *"You are now a developer!"*

### Step 5 — Enable USB Debugging

1. Go back to **Settings**
2. Tap **Developer Options** (may be under Settings → System on some phones)
3. Toggle **USB Debugging** → ON

---

## Part 4 — Running an Android Scan

### Step 1 — Connect your phone

Plug your Android phone into your PC using a **USB data cable** (not a charge-only cable).

### Step 2 — Trust the PC on your phone

A popup appears on your phone:
> *"Allow USB debugging from this computer?"*

- Check **"Always allow from this computer"**
- Tap **Allow**

### Step 3 — Confirm the connection

```powershell
adb devices
```

Expected output:
```
List of devices attached
R5CX123ABC    device
```

The word **`device`** means connected and trusted. If you see `unauthorized`, the trust popup wasn't accepted — unplug, check your phone screen, replug.

### Step 4 — Open the Android Scanner tab

1. Go to `http://localhost:8000`
2. Click the **📱 Android Scanner** tab

### Step 5 — Detect and scan

1. Click **🔍 Detect Device** — your phone model should appear with a green **Connected** pill
2. Click **▶ Start Scan**

The scan runs through 4 stages shown on screen:
1. 📋 Fingerprinting device
2. 📦 Reading installed packages
3. 🔍 Matching CVE database
4. 📊 Building report

> Scan takes **30–90 seconds** depending on how many apps are installed.

---

## Part 5 — Reading the Scan Report

### Severity Summary
Shows Critical / High / Medium / Low / Total counts for your specific device.

### Vulnerability Categories

| Tag | What it means |
|---|---|
| 🤖 Android OS | Affects your Android version — published after your security patch date |
| 🐧 Kernel | Affects the Linux kernel that Android runs on |
| 🏭 Manufacturer | Specific to your phone's brand (Samsung, Xiaomi, etc.) |
| 📦 Apps | Matches an app installed on your phone |

### Why "after security patch date"?

Your phone has a **Security Patch Date** (e.g. `2024-10-01`).
Google releases monthly patches that fix CVEs up to that date.
The scanner only shows CVEs published **after** your patch date — meaning they are not yet fixed on your device.
CVEs before your patch date are already patched.

### Filtering results

- Use the **Filter dropdown** to show a specific severity or category
- Click the **category pills** to isolate Android OS / Kernel / Manufacturer / App CVEs
- Click **Details** on any CVE for full description + remediation steps

### Scan History

Scroll down on the Android Scanner tab to see **Previous Scans** — model, Android version, patch date, and vulnerability counts for each past session.

---

## Configuration

All config lives in `.env` at the project root:

```env
# Free NVD API key — get one at https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your-key-here

# How often to auto-refresh CVEs in the background (minutes)
REFRESH_INTERVAL_MINUTES=30
```

---

## API Reference

The backend exposes a REST API at `http://localhost:8000`:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Serves the dashboard |
| GET | `/api/stats` | Aggregate CVE counts by severity |
| GET | `/api/cves` | Paginated CVE list with filters |
| GET | `/api/cves/{cve_id}` | Full detail for one CVE |
| POST | `/api/refresh` | Trigger a manual CVE fetch |
| GET | `/api/stream` | Server-Sent Events live update stream |
| GET | `/api/android/status` | ADB availability + connected devices |
| POST | `/api/android/scan` | Run a full Android vulnerability scan |
| GET | `/api/android/history` | Past Android scan summaries |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `adb` not recognized | Add `C:\platform-tools\platform-tools` to system PATH, open a new PowerShell window |
| Phone shows `unauthorized` in `adb devices` | Unplug, check phone screen for trust popup, tap Allow, replug |
| Dashboard blank / no CVEs | Initial fetch still running — check the PowerShell terminal for progress |
| Scan takes very long | Normal for 100+ apps — wait up to 2 minutes |
| `No device connected` in dashboard | Run `adb devices` in PowerShell first to confirm connection |
| ADB not found error in dashboard | ADB not in PATH — restart the server after adding to PATH |
| Port 8000 already in use | Another process is using port 8000 — stop it or change the port in `start.ps1` |

---

## Data Sources

| Source | URL | Used for |
|---|---|---|
| NIST NVD API v2 | https://services.nvd.nist.gov/rest/json/cves/2.0 | Full CVE database — scores, descriptions, CPE data |
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Actively exploited vulnerability list |

All data is stored locally in `data/cvewatch.db` (SQLite). No data ever leaves your machine.

---

## Commit History

| Phase | What was built |
|---|---|
| Phase 1 | Live CVE dashboard — NVD fetch, SQLite, SSE, dark-mode UI, filters, detail modal, remediation |
| Phase 2 | Android USB scanner — ADB bridge, device fingerprint, CVE matching, scan report, scan history |
