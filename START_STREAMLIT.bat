@echo off
REM ===================================================================
REM  PhishGuard Streamlit - one-click start
REM  Double-click this file to run the Streamlit app and open in browser.
REM ===================================================================
setlocal
cd /d "%~dp0"
title PhishGuard Streamlit App

echo.
echo  ==============================================
echo   PhishGuard - Streamlit Phishing URL Scanner
echo  ==============================================
echo.

REM --- 1. Find a Python interpreter ---
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
    pause
    exit /b 1
)

REM --- 2. Check if streamlit is installed ---
"%PY%" -c "import streamlit" >nul 2>nul
if errorlevel 1 (
    echo  Installing Streamlit and dependencies...
    "%PY%" -m pip install -r requirements.txt
)

REM --- 3. Start Streamlit ---
echo  Starting Streamlit at http://localhost:8501 ...
echo.
"%PY%" -m streamlit run streamlit_app.py

pause
