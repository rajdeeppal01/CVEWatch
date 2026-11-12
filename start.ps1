# CVEWatch — Start Script (PowerShell)
# Run this once to install deps, then it starts the server.

$Root = $PSScriptRoot

Write-Host ""
Write-Host "  ⬡  CVEWatch — Live CVE Dashboard" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────" -ForegroundColor DarkCyan
Write-Host ""

# 1. Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "  [ERROR] Python not found. Install Python 3.11+ first." -ForegroundColor Red
    exit 1
}

# 2. Create venv if needed
$venvPath = Join-Path $Root ".venv"
if (-not (Test-Path $venvPath)) {
    Write-Host "  Creating virtual environment..." -ForegroundColor Yellow
    python -m venv $venvPath
}

# 3. Activate venv
$activate = Join-Path $venvPath "Scripts\Activate.ps1"
. $activate

# 4. Install dependencies
Write-Host "  Installing dependencies..." -ForegroundColor Yellow
pip install -r "$Root\backend\requirements.txt" -q

# 5. Start server
Write-Host ""
Write-Host "  Starting CVEWatch on http://localhost:8000" -ForegroundColor Green
Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

Set-Location "$Root\backend"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
