@echo off
cd /d "%~dp0.."

REM Load PORT from .env if present, default 8080
set PORT=8080
for /f "tokens=1,2 delims==" %%a in (.env) do (
    if "%%a"=="PORT" set PORT=%%b
)

echo Starting Aegis Portal on port %PORT%...
docker-compose up -d
if errorlevel 1 (
    echo.
    echo Failed to start. Is Docker Desktop running?
    pause
    exit /b 1
)
echo.
echo Portal is running at http://localhost:%PORT%
echo.
echo Run windows\stop.bat to shut it down.
echo Run windows\update.bat to pull the latest version.
echo.
