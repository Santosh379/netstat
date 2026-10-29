# NetScope AI PowerShell Launcher
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "        NetScope AI - Network Threat Monitoring System   " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python 3 was not found in your PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.12 from https://python.org."
    pause
    exit 1
}

# 2. Check Node
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Node.js was not found in your PATH." -ForegroundColor Red
    Write-Host "Please install Node.js from https://nodejs.org."
    pause
    exit 1
}

# 3. Start Backend in separate window
Write-Host "[INFO] Starting FastAPI Backend on http://127.0.0.1:8000 ..." -ForegroundColor Green
Start-Process python -ArgumentList "backend/run_backend.py" -WindowStyle Normal

Start-Sleep -Seconds 2

# 4. Open default browser
Write-Host "[INFO] Opening http://localhost:5173 in browser..." -ForegroundColor Green
Start-Process "http://localhost:5173"

# 5. Start Frontend
Write-Host "[INFO] Starting Vite Frontend Server..." -ForegroundColor Green
npm run dev
