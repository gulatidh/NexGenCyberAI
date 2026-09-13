@echo off
setlocal
echo ============================================================
echo  Aegis Portal -- First-Time Setup
echo ============================================================
echo.

REM Check Docker is installed and running
docker --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker Desktop is not installed or not running.
    echo Download from: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker Desktop is installed but not running.
    echo Please start Docker Desktop and try again.
    pause
    exit /b 1
)

REM Check git
git --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed.
    echo Download from: https://git-scm.com/download/win
    pause
    exit /b 1
)

REM Move to repo root
cd /d "%~dp0.."

REM Copy .env.example to .env if it doesn't exist
if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo.
    echo IMPORTANT: Edit .env with your Azure AD and AI provider settings.
    echo.
    set /p openenv="Open .env in Notepad now? (Y/N): "
    if /i "%openenv%"=="Y" notepad .env
    echo.
    echo Press any key when you have saved .env to continue...
    pause >nul
) else (
    echo .env already exists -- skipping copy.
)

echo.
echo Building Docker image (this may take 5-15 minutes on first run)...
echo.
docker-compose build
if errorlevel 1 (
    echo.
    echo BUILD FAILED. Check the output above for errors.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Setup complete!
echo ============================================================
echo.
echo  Run  windows\start.bat  to launch the portal.
echo.
echo  IMPORTANT: Before logging in, add the redirect URI to your
echo  Azure AD App Registration:
echo.
echo    Azure Portal -^> App Registrations -^> [your app]
echo    -^> Authentication -^> Single-page application
echo    -^> Add URI: http://localhost:8080
echo.
pause
