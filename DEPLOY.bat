@echo off
REM ===================================================================
REM  PhishGuard - push your changes to GitHub (which then auto-deploys)
REM  Double-click this file after making changes, then type a message.
REM ===================================================================
setlocal
cd /d "%~dp0"
title PhishGuard Deploy

echo.
echo  ==============================================
echo   PhishGuard - deploy to GitHub
echo  ==============================================
echo.

if not exist ".git" (
    echo  [ERROR] This folder is not a git repository.
    echo  See the Deploy section of README.md.
    pause
    exit /b 1
)

echo  Current changes:
echo.
git status --short
echo.

set "MSG="
set /p "MSG=Describe this update (or press Enter for default): "
if "%MSG%"=="" set "MSG=Update PhishGuard"

echo.
echo  [1/3] Staging files...
git add -A
if errorlevel 1 goto failed

echo  [2/3] Saving a snapshot...
git commit -m "%MSG%"
if errorlevel 1 (
    echo.
    echo  Nothing new to save, or the commit failed ^(see above^).
    echo  Continuing to push in case earlier commits are waiting...
)

echo  [3/3] Uploading to GitHub...
git push origin main
if errorlevel 1 goto failed

echo.
echo  Done! GitHub now has your latest code.
echo  If this repo is connected to Render/Railway, it will redeploy
echo  automatically in a minute or two.
echo.
pause
exit /b 0

:failed
echo.
echo  [ERROR] Something went wrong. Read the message above.
echo  If it mentions rejected/non-fast-forward, run:  git pull --rebase origin main
echo.
pause
exit /b 1
