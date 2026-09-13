@echo off
cd /d "%~dp0.."
echo ============================================================
echo  Aegis Portal -- Update to Latest Version
echo ============================================================
echo.
echo Pulling latest changes from GitHub...
git pull origin main
if errorlevel 1 (
    echo.
    echo Git pull failed. Check your internet connection or run as a
    echo user with access to the repository.
    pause
    exit /b 1
)
echo.
echo Rebuilding Docker image with latest code...
echo (This may take a few minutes)
echo.
docker-compose up --build -d
if errorlevel 1 (
    echo.
    echo Rebuild failed. Check the output above.
    pause
    exit /b 1
)
echo.
echo ============================================================
echo  Update complete. Portal restarted with latest version.
echo ============================================================
echo.
echo Your data in the Docker volume is untouched.
echo NOTE: docker-compose down -v would delete your database -- avoid it.
echo.
