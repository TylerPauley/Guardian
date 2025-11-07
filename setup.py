#!/usr/bin/env python3
"""
Setup script for Guardian FIM system.
"""

import os
import sys
import shutil
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 7):
        print("Error: Guardian FIM requires Python 3.7 or higher")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"[OK] Python version: {sys.version.split()[0]}")


def create_directories():
    """Create necessary directories."""
    directories = [
        'logs',
        'reports',
        'backups'
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"[OK] Created directory: {directory}")
        else:
            print(f"[OK] Directory already exists: {directory}")


def setup_configuration():
    """Setup configuration file if it doesn't exist."""
    config_file = 'guardian.conf'
    
    if os.path.exists(config_file):
        print(f"[OK] Configuration file {config_file} already exists")
        return
    
    # Create a basic configuration file
    config_content = """[DEFAULT]
# Database file for storing baselines
database_file = guardian_baseline.db

# Logging configuration
log_file = guardian.log
log_level = INFO

# Hash algorithms to use (comma-separated)
hash_algorithms = sha256,sha1,md5

# File patterns to exclude from scanning (comma-separated)
exclude_patterns = *.tmp,*.log,*.cache,*.swp,.DS_Store,Thumbs.db,*.pyc,__pycache__

# Maximum file size to scan (B, KB, MB, GB)
max_file_size = 100MB

# Scan timeout in seconds
scan_timeout = 300

[PATHS]
# Paths to monitor (comma-separated)
monitor_paths = /etc,/var/log,/home

# Paths to exclude from monitoring (comma-separated)
exclude_paths = /proc,/sys,/dev,/tmp,/var/tmp

[REPORTING]
# Output format: console, json, html
output_format = console

# Generate detailed reports
detailed_report = true

# Alert on critical file changes
alert_on_critical = true

# Critical files that should trigger alerts (comma-separated)
critical_paths = /etc/passwd,/etc/shadow,/etc/sudoers,/etc/hosts,/etc/ssh/sshd_config
"""
    
    with open(config_file, 'w') as f:
        f.write(config_content)
    
    print(f"[OK] Created configuration file: {config_file}")


def make_executable():
    """Make Guardian scripts executable."""
    scripts = ['guardian.py', 'example_usage.py', 'test_guardian.py']
    
    for script in scripts:
        if os.path.exists(script):
            # On Unix-like systems, make executable
            if os.name != 'nt':  # Not Windows
                os.chmod(script, 0o755)
            print(f"[OK] Made executable: {script}")


def run_tests():
    """Run the test suite."""
    print("\n" + "=" * 50)
    print("RUNNING TEST SUITE")
    print("=" * 50)
    
    try:
        import subprocess
        result = subprocess.run([sys.executable, 'test_guardian.py'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[OK] All tests passed!")
        else:
            print("[ERROR] Some tests failed:")
            print(result.stdout)
            print(result.stderr)
            
    except Exception as e:
        print(f"[ERROR] Error running tests: {e}")


def create_sample_scripts():
    """Create sample monitoring scripts."""
    
    # Create a simple monitoring script
    monitor_script = """#!/bin/bash
# Simple Guardian monitoring script
# Usage: ./monitor.sh <path_to_monitor>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <path_to_monitor>"
    echo "Example: $0 /etc"
    exit 1
fi

MONITOR_PATH="$1"
BASELINE_NAME="auto_baseline_$(date +%Y%m%d_%H%M%S)"

echo "Guardian FIM - Automated Monitoring"
echo "Monitoring path: $MONITOR_PATH"
echo "Baseline name: $BASELINE_NAME"
echo

# Create baseline if it doesn't exist
if [ ! -f "guardian_baseline.db" ]; then
    echo "Creating baseline..."
    python3 guardian.py --baseline --path "$MONITOR_PATH" --name "$BASELINE_NAME"
    if [ $? -eq 0 ]; then
        echo "[OK] Baseline created successfully"
    else
        echo "[ERROR] Failed to create baseline"
        exit 1
    fi
else
    echo "[OK] Baseline already exists"
fi

# Check integrity
echo "Checking integrity..."
python3 guardian.py --check --path "$MONITOR_PATH" --save-report

if [ $? -eq 0 ]; then
    echo "[OK] No changes detected"
else
    echo "[WARNING] Changes detected - check the generated report"
fi
"""
    
    with open('monitor.sh', 'w', encoding='utf-8') as f:
        f.write(monitor_script)
    
    # Make executable on Unix-like systems
    if os.name != 'nt':
        os.chmod('monitor.sh', 0o755)
    
    print("[OK] Created sample monitoring script: monitor.sh")
    
    # Create Windows batch file version
    monitor_bat = """@echo off
REM Simple Guardian monitoring script for Windows
REM Usage: monitor.bat <path_to_monitor>

if "%~1"=="" (
    echo Usage: %0 ^<path_to_monitor^>
    echo Example: %0 C:\\Windows\\System32
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
"""
    
    with open('monitor.bat', 'w', encoding='utf-8') as f:
        f.write(monitor_bat)
    
    print("[OK] Created Windows batch script: monitor.bat")


def main():
    """Main setup function."""
    print("GUARDIAN FIM - SETUP SCRIPT")
    print("=" * 50)
    print("Setting up Guardian File Integrity Monitor...")
    print()
    
    # Check Python version
    check_python_version()
    
    # Create directories
    print("\nCreating directories...")
    create_directories()
    
    # Setup configuration
    print("\nSetting up configuration...")
    setup_configuration()
    
    # Make scripts executable
    print("\nMaking scripts executable...")
    make_executable()
    
    # Create sample scripts
    print("\nCreating sample scripts...")
    create_sample_scripts()
    
    # Run tests
    run_tests()
    
    print("\n" + "=" * 50)
    print("SETUP COMPLETED SUCCESSFULLY")
    print("=" * 50)
    print("Guardian FIM is ready to use!")
    print()
    print("Quick start:")
    print("1. Run the example: python3 example_usage.py")
    print("2. Create a baseline: python3 guardian.py --baseline /path/to/monitor")
    print("3. Check integrity: python3 guardian.py --check /path/to/monitor")
    print()
    print("For more information, see README.md")


if __name__ == "__main__":
    main()
