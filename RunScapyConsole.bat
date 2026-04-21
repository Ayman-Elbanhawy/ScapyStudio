@echo off
setlocal EnableExtensions

set "APP_ROOT=%~dp0"
if "%APP_ROOT:~-1%"=="\" set "APP_ROOT=%APP_ROOT:~0,-1%"
set "APP_VENV=%APP_ROOT%\.venv"

cd /d "%APP_ROOT%"

if not exist "%APP_VENV%\Scripts\python.exe" (
    echo The Scapy Studio virtual environment was not found.
    echo Run StartMe.bat first so dependencies are installed.
    pause
    exit /b 1
)

call "%APP_VENV%\Scripts\activate.bat"
python -m scapy
