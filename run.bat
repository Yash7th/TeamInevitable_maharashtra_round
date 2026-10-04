@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo          ModelLedger - Web3 AI Provenance Tracker
echo =======================================================
echo.

:: Ensure working directory is the script directory
cd /d "%~dp0model-ledger"

:: Check if python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in system PATH.
    echo Please install Python 3.10 or higher from https://python.org
    pause
    exit /b 1
)

echo [1/3] Checking Python environment...
python --version

echo.
echo [2/3] Installing and verifying required dependencies...
python -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [WARNING] Standard pip install encountered warnings, continuing...
)

echo.
echo [3/3] Launching ModelLedger application...
echo -------------------------------------------------------
echo Application starting at http://localhost:8501
echo Press Ctrl+C in this terminal to stop the server.
echo -------------------------------------------------------
echo.

python -m streamlit run app.py

pause
