@echo off
setlocal enabledelayedexpansion
title NetScope AI - Launcher
echo ========================================================
echo         NetScope AI - Network Threat Monitoring System
echo ========================================================
echo.

:: 1. Check Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 is not found in your PATH!
    echo Please install Python 3.12 from https://python.org and check "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

:: 2. Check Node.js
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not found in your PATH!
    echo Please install Node.js (v18+) from https://nodejs.org.
    echo.
    pause
    exit /b 1
)

:: 3. Determine Python Environment
set PYTHON_EXEC=python
if exist ".venv\Scripts\python.exe" (
    set PYTHON_EXEC=.venv\Scripts\python.exe
) else (
    :: Test if required packages are installed in current python
    python -c "import fastapi, scapy, dpkt, psutil" >nul 2>nul
    if !errorlevel! neq 0 (
        echo [INFO] Creating Python virtual environment in .venv...
        python -m venv .venv
        if !errorlevel! neq 0 (
            echo [WARNING] Failed to create virtual environment, trying global pip install...
            python -m pip install -r backend\requirements.txt
        ) else (
            set PYTHON_EXEC=.venv\Scripts\python.exe
            echo [INFO] Installing backend dependencies...
            call .venv\Scripts\pip install -r backend\requirements.txt
        )
    )
)

:: 4. Check Node modules
if not exist node_modules (
    echo [INFO] Installing frontend dependencies (npm install)...
    call npm install
)

:: 5. Launch Backend
echo [INFO] Starting FastAPI Backend on http://127.0.0.1:8000 ...
start "NetScope AI - Backend Server" %PYTHON_EXEC% backend/run_backend.py

:: 6. Wait for backend to initialize
echo [INFO] Waiting for backend to initialize...
timeout /t 2 /nobreak >nul

:: 7. Launch Frontend
echo [INFO] Starting Vite Frontend on http://localhost:5173 ...
start http://localhost:5173
call npm run dev

pause
