@echo off
REM Must be run as Administrator to register a scheduled task.
cd /d "%~dp0"
set SCRIPT_PATH=%~dp0update.bat
set TASK_NAME=AegisPortalAutoUpdate

echo Registering daily auto-update task (2:00 AM)...
echo Task will run: %SCRIPT_PATH%
echo.

schtasks /create /tn "%TASK_NAME%" /tr "\"%SCRIPT_PATH%\"" /sc daily /st 02:00 /f /rl highest
if errorlevel 1 (
    echo.
    echo Failed to register task. Try right-clicking and selecting
    echo "Run as administrator".
    pause
    exit /b 1
)

echo.
echo Auto-update scheduled successfully.
echo   Task name : %TASK_NAME%
echo   Schedule  : Daily at 02:00 AM
echo   To remove : schtasks /delete /tn "%TASK_NAME%" /f
echo.
pause
