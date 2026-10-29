@echo off
REM ===================================================================
REM  PhishGuard - one-click start
REM  Double-click this file to run the app and open it in a browser.
REM ===================================================================
setlocal
cd /d "%~dp0"
title PhishGuard Server

echo.
echo  ==============================================
echo   PhishGuard - Phishing URL Detection
echo  ==============================================
echo.

REM --- 1. Find a Python interpreter ---------------------------------
set "PY="
if exist ".venv312\Scripts\python.exe" set "PY=.venv312\Scripts\python.exe"
if not defined PY if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY (
    where python >nul 2>nul
    if not errorlevel 1 set "PY=python"
)
if not defined PY (
    echo  [ERROR] Python was not found.
    echo  Install Python 3.10+ from https://www.python.org/downloads/
    echo  and tick "Add Python to PATH", then run this file again.
    echo.
    pause
    exit /b 1
)

REM --- 2. Make sure Flask is installed ------------------------------
"%PY%" -c "import flask" >nul 2>nul
if errorlevel 1 (
    echo  First run: installing Flask... this takes about a minute.
    "%PY%" -m pip install --disable-pip-version-check -q -r requirements.txt
    if errorlevel 1 (
        echo.
        echo  [ERROR] Installing dependencies failed.
        echo  Try running this command manually to see the full message:
        echo      "%PY%" -m pip install -r requirements.txt
        echo.
        pause
        exit /b 1
    )
    echo  Dependencies installed.
    echo.
)

REM --- 3. Open the browser a few seconds after the server starts ---
start "" /b cmd /c "timeout /t 3 >nul & start http://127.0.0.1:5000"

REM --- 4. Run the server (Ctrl+C here to stop it) -------------------
echo  Starting PhishGuard at http://127.0.0.1:5000
echo  Your browser should open automatically.
echo.
echo  To STOP the app: press Ctrl+C in this window, or just close it.
echo.
"%PY%" app.py

echo.
echo  Server stopped.
pause
