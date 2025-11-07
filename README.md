# 🛡️ Guardian - File Integrity Monitor (FIM)

A comprehensive **Host-Based Intrusion Detection System (HIDS)** tool for monitoring file system changes and ensuring system integrity.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
  - [Core Functionality](#core-functionality)
  - [Advanced Features](#advanced-features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
- [Usage](#usage)
  - [Command Line Interface](#command-line-interface)
    - [Create a Baseline](#create-a-baseline)
    - [Check Integrity](#check-integrity)
  - [Programmatic Usage](#programmatic-usage)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Technical Architecture](#technical-architecture)
  - [Core Classes](#core-classes)
  - [Data Models](#data-models)
  - [Database Schema](#database-schema)
- [Output Formats](#output-formats)
  - [Console Output](#console-output)
  - [JSON Output](#json-output)
  - [HTML Output](#html-output)
- [Use Cases](#use-cases)
  - [System Administration](#system-administration)
  - [Web Server Security](#web-server-security)
  - [Development Environments](#development-environments)
  - [Compliance & Auditing](#compliance--auditing)
- [Security Considerations](#security-considerations)
  - [Detects](#detects)
  - [Does Not Detect](#does-not-detect)
  - [Best Practices](#best-practices)
- [Advanced Usage](#advanced-usage)
- [Testing & Quality](#testing--quality)
- [Skills Demonstrated](#skills-demonstrated)
- [Troubleshooting](#troubleshooting)
- [Future Enhancements](#future-enhancements)
- [Development](#development)
- [License](#license)
- [Support](#support)
- [Changelog](#changelog)

---

## Overview

**Guardian** is a Python-based File Integrity Monitor that creates baselines of your file system and continuously monitors for unauthorized changes.  
It’s designed to detect potential security breaches, malware infections, and unauthorized system modifications by tracking file changes at the **cryptographic hash** level.

---

## Features

### Core Functionality
- ✅ **Baseline Creation** – Create cryptographic baselines using SHA256, SHA1, and MD5 hashes  
- ✅ **Integrity Checking** – Compare current file states against established baselines  
- ✅ **Change Detection** – Identify added, modified, and removed files  
- ✅ **Comprehensive Reporting** – Output reports to console, JSON, or HTML  

### Advanced Features
- ✅ **Configurable Exclusions** – Skip temporary files, logs, and non-critical paths  
- ✅ **Multiple Hash Algorithms** – SHA256, SHA1, MD5  
- ✅ **SQLite Database** – Efficient and portable storage  
- ✅ **Comprehensive Logging** – Adjustable verbosity  
- ✅ **Performance Optimization** – Chunked reads for large files  
- ✅ **Critical File Monitoring** – Alerts for sensitive files  
- ✅ **Change History** – Persistent historical tracking  
- ✅ **Cross-Platform** – Windows, Linux, and macOS  
- ✅ **Zero Dependencies** – 100% Python standard library  

---

## Installation

### Prerequisites
- Python **3.7+**
- Only standard library modules (no external installs)

### Quick Start

```bash
# Create a baseline
python guardian.py --baseline /etc --name "system_config_baseline"

# Check integrity
python guardian.py --check /etc
```

---

## Usage

### Command Line Interface

#### Create a Baseline
```bash
python guardian.py --baseline <path> [--name <baseline_name>]
```

**Examples:**
```bash
# System configuration
python guardian.py --baseline /etc --name "system_config_baseline"

# Web server files
python guardian.py --baseline /var/www --name "web_files_baseline"

# Auto-generate baseline name
python guardian.py --baseline /home/user/documents
```

#### Check Integrity
```bash
python guardian.py --check <path> [--output <format>] [--save-report] [--fail-on-changes]
```

**Examples:**
```bash
# Basic check
python guardian.py --check /etc

# JSON output
python guardian.py --check /etc --output json

# Save report to file
python guardian.py --check /etc --save-report

# Exit with error if changes detected
python guardian.py --check /etc --fail-on-changes
```

---

### Programmatic Usage

Guardian can also be imported and used directly:

```python
from guardian import Guardian

# Initialize Guardian
guardian = Guardian()

# Create baseline
baseline_id = guardian.create_baseline("/path/to/monitor", "my_baseline")

# Check integrity
changes = guardian.check_integrity("/path/to/monitor")

# Generate report
report = guardian.reporter.generate_report(changes, "json")
print(report)
```

---

## Configuration

**guardian.conf**
```ini
[DEFAULT]
database_file = guardian_baseline.db
log_file = guardian.log
log_level = INFO
hash_algorithms = sha256,sha1,md5
exclude_patterns = *.tmp,*.log,*.cache,*.swp,.DS_Store,Thumbs.db
max_file_size = 100MB

[PATHS]
monitor_paths = /etc,/var/log,/home
exclude_paths = /proc,/sys,/dev,/tmp

[REPORTING]
output_format = console
detailed_report = true
alert_on_critical = true
critical_paths = /etc/passwd,/etc/shadow,/etc/sudoers
```

---

## Project Structure

```
Guardian/
├── guardian.py           # Main application (500+ lines)
├── guardian.conf         # Configuration file
├── test_guardian.py      # Comprehensive test suite
├── example_usage.py      # Interactive demonstration
├── setup.py              # Setup script
├── requirements.txt      # Minimal (stdlib only)
├── README.md             # Documentation
└── monitor.sh            # Sample monitoring script
```

---

## Technical Architecture

### Core Classes
- **Guardian** – Main controller  
- **GuardianConfig** – Configuration handling  
- **GuardianDatabase** – SQLite operations  
- **GuardianScanner** – File scanning and hashing  
- **GuardianReporter** – Reporting in console/JSON/HTML  

### Data Models
- `FileInfo` – File metadata and hashes  
- `ChangeReport` – Change detection results  
- `ChangeType` – Enum: ADDED, MODIFIED, REMOVED  

### Database Schema
- `baselines` – Baseline metadata  
- `files` – File information and hashes  
- `change_history` – Historical tracking  

---

## Output Formats

### Console Output
```
============================================================
GUARDIAN FILE INTEGRITY MONITOR - CHANGE REPORT
============================================================
Scan completed at: 2024-01-15 14:30:25
Total changes detected: 3

[ADDED]
  /etc/new_config.conf

[MODIFIED]
  /etc/passwd
    Old hash: 5d41402abc4b2a76b9719d911017c592...
    New hash: 098f6bcd4621d373cade4e832627b4f6...

[REMOVED]
  /etc/old_config.conf
```

### JSON Output
```json
{
  "timestamp": "2024-01-15T14:30:25.123456",
  "total_changes": 3,
  "changes": [
    {
      "change_type": "ADDED",
      "file_path": "/etc/new_config.conf",
      "new_hash": "abc123...",
      "timestamp": "2024-01-15T14:30:25.123456"
    }
  ]
}
```

### HTML Output
Generates a complete, styled report suitable for email or web dashboards.

---

## Use Cases

### System Administration
- Monitor `/etc`, `/usr/bin`, `/sbin`  
- Detect config changes  
- Track file modifications  

### Web Server Security
- Monitor `/var/www`  
- Detect unauthorized web code changes  
- Validate deployment integrity  

### Development Environments
- Watch source directories  
- Detect unapproved edits  
- Verify build artifacts  

### Compliance & Auditing
- Generate audit trails  
- Track changes for compliance  
- Monitor sensitive business files  

---

## Security Considerations

### Detects
- File **modifications**, **additions**, **deletions**
- **Permission** and **ownership** changes

### Does Not Detect
- In-memory modifications  
- Network activity  
- Running process changes  
- Windows Registry edits  

### Best Practices
- Regular baseline updates  
- Focus on critical directories  
- Tune exclusion patterns  
- Schedule automated scans  
- Protect baseline databases  

---

## Advanced Usage

### Automated Monitoring (`monitor.sh`)
```bash
#!/bin/bash
BASELINE_PATH="/etc"
REPORT_DIR="/var/log/guardian"

if [ ! -f "guardian_baseline.db" ]; then
    python guardian.py --baseline "$BASELINE_PATH" --name "auto_baseline_$(date +%Y%m%d)"
fi

python guardian.py --check "$BASELINE_PATH" --save-report --output json
mv guardian_report_*.txt "$REPORT_DIR/"
```

### Integration with Monitoring Systems
```bash
python guardian.py --check /etc --fail-on-changes
if [ $? -ne 0 ]; then
    curl -X POST "https://monitoring.example.com/alerts"          -H "Content-Type: application/json"          -d '{"alert": "File integrity violation detected"}'
fi
```

---

## Testing & Quality

- ✅ 7 test classes (`test_guardian.py`)  
- ✅ Full workflow integration tests  
- ✅ Robust error handling  
- ✅ Cross-platform support  
- ✅ 100% standard library  

---

## Skills Demonstrated

### Cybersecurity
- File Integrity Monitoring  
- Cryptographic Hashing (SHA256/SHA1/MD5)  
- System Auditing & HIDS Design  

### Python Development
- Object-Oriented Architecture  
- SQLite database integration  
- Argparse CLI design  
- Logging & configuration management  
- Dataclasses, enums, type hints  
- Exception handling  

### Software Engineering
- Modular and extensible design  
- Config-driven architecture  
- Full documentation & testing  

---

## Troubleshooting

### "No baseline found for path"
- **Cause:** Baseline not created  
- **Fix:** Run with `--baseline` first  

### "Permission denied"
- **Cause:** Insufficient privileges  
- **Fix:** Run as admin/root  

### Large file exclusions
- **Fix:** Adjust `max_file_size` or exclusions  

### Performance issues
- **Fix:** Narrow monitored scope  

### Log Example
```
2024-01-15 14:30:25,123 - guardian - INFO - Creating baseline '/etc'
2024-01-15 14:30:25,456 - guardian - INFO - Scanned 1,234 files
2024-01-15 14:30:25,789 - guardian - INFO - Baseline created successfully
```

---

## Future Enhancements
- Email/SMS alerts  
- Webhook integrations  
- Real-time monitoring  
- Web dashboard  
- SIEM integration  
- Advanced filtering  

---

## Development

### Run Tests
```bash
python test_guardian.py
```

### Contributing
1. Fork repository  
2. Create feature branch  
3. Add tests  
4. Submit pull request  

---

## License
This project is open source under the **MIT License**.

---

## Support
- Review troubleshooting section  
- Check example test cases  
- Open a GitHub issue  

---

## Changelog

### v1.0.0
- Initial release  
- Core FIM functionality  
- Multi-format reporting  
- SQLite baseline storage  
- Full test coverage
