@echo off
REM Simple Guardian monitoring script for Windows
REM Usage: monitor.bat <path_to_monitor>

if "%~1"=="" (
    echo Usage: %0 ^<path_to_monitor^>
    echo Example: %0 C:\Windows\System32
    exit /b 1
)

set MONITOR_PATH=%~1
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do set "date=%%c%%a%%b"
for /f "tokens=1-2 delims=: " %%a in ('time /t') do set "time=%%a%%b"
set "BASELINE_NAME=auto_baseline_%date%_%time%"

echo Guardian FIM - Automated Monitoring
echo Monitoring path: %MONITOR_PATH%
echo Baseline name: %BASELINE_NAME%
echo.

REM Create baseline if it doesn't exist
if not exist "guardian_baseline.db" (
    echo Creating baseline...
    python guardian.py --baseline --path "%MONITOR_PATH%" --name "%BASELINE_NAME%"
    if %errorlevel% equ 0 (
        echo [OK] Baseline created successfully
    ) else (
        echo [ERROR] Failed to create baseline
        exit /b 1
    )
) else (
    echo [OK] Baseline already exists
)

REM Check integrity
echo Checking integrity...
python guardian.py --check --path "%MONITOR_PATH%" --save-report

if %errorlevel% equ 0 (
    echo [OK] No changes detected
) else (
    echo [WARNING] Changes detected - check the generated report
)
