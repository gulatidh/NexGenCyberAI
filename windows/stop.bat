@echo off
cd /d "%~dp0.."
echo Stopping Aegis Portal...
docker-compose down
echo Done. Your data is preserved in the Docker volume.
echo Run windows\start.bat to start again.
echo.
