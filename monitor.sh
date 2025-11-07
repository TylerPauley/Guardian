#!/bin/bash
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
