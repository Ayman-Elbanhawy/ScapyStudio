@echo off
setlocal EnableExtensions

set "APP_NAME=Scapy Studio"
set "APP_ROOT=%~dp0"
if "%APP_ROOT:~-1%"=="\" set "APP_ROOT=%APP_ROOT:~0,-1%"

set "APP_SOURCE=%APP_ROOT%\scapy_studio"
set "APP_VENV=%APP_ROOT%\.venv"
set "PYTHON_EXE=%APP_VENV%\Scripts\python.exe"
set "PIP_INDEX_URL=https://pypi.org/simple"
set "READY_MARKER=%APP_VENV%\.studio-ready"
set "DOWNLOAD_ROOT=%APP_ROOT%\.downloads"
set "NPCAP_INSTALLER=%DOWNLOAD_ROOT%\npcap-latest.exe"
set "NPCAP_URL=https://npcap.com/dist/npcap-latest.exe"

echo.
echo Launching %APP_NAME%
echo Application folder: %APP_ROOT%
echo.

if not exist "%APP_VENV%\Scripts\python.exe" (
    echo Creating virtual environment...
    py -3 -m venv "%APP_VENV%"
    if errorlevel 1 (
        echo Failed to create Python virtual environment.
        pause
        exit /b 1
    )
)

if not exist "%PYTHON_EXE%" (
    echo Python executable was not created successfully.
    pause
    exit /b 1
)

if not exist "%READY_MARKER%" (
    echo Installing Python dependencies...
    "%PYTHON_EXE%" -m pip install --index-url "%PIP_INDEX_URL%" --upgrade pip setuptools wheel
    if errorlevel 1 exit /b 1

    "%PYTHON_EXE%" -m pip install --index-url "%PIP_INDEX_URL%" --no-build-isolation -e "%APP_ROOT%"
    if errorlevel 1 exit /b 1

    "%PYTHON_EXE%" -m pip install --index-url "%PIP_INDEX_URL%" -r "%APP_ROOT%\requirements-studio.txt"
    if errorlevel 1 exit /b 1

    echo Compiling desktop modules...
    "%PYTHON_EXE%" -m compileall "%APP_SOURCE%"
    if errorlevel 1 exit /b 1

    > "%READY_MARKER%" echo ready
)

where NpcapHelper.exe >nul 2>nul
if errorlevel 1 (
    echo Npcap was not detected. Offline PCAP review will still work.
    echo Live capture on Windows requires Npcap.
    if not exist "%DOWNLOAD_ROOT%" mkdir "%DOWNLOAD_ROOT%"
    if not exist "%NPCAP_INSTALLER%" (
        echo Downloading Npcap installer...
        powershell -NoProfile -ExecutionPolicy Bypass -Command ^
          "Invoke-WebRequest -Uri '%NPCAP_URL%' -OutFile '%NPCAP_INSTALLER%'"
    )
    if exist "%NPCAP_INSTALLER%" (
        echo Opening Npcap installer: %NPCAP_INSTALLER%
        start "" "%NPCAP_INSTALLER%"
    )
)

echo.
echo Starting %APP_NAME% GUI...
start "%APP_NAME%" "%PYTHON_EXE%" -m scapy_studio
exit /b 0
