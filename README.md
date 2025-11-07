# Guardian - File Integrity Monitor (FIM)

A comprehensive host-based intrusion detection system (HIDS) tool for monitoring file system changes and ensuring system integrity.

---

## Table of Contents
- [🛡️ Overview](#overview)
- [🚀 Features](#features)
  - [Core Functionality](#core-functionality)
  - [Advanced Features](#advanced-features)
- [⚙️ Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
- [🎮 Usage](#usage)
  - [Command Line Interface](#command-line-interface)
    - [Create a Baseline](#create-a-baseline)
    - [Check Integrity](#check-integrity)
  - [Programmatic Usage](#programmatic-usage)
- [🔧 Configuration](#configuration)
- [📁 Project Structure](#project-structure)
- [🏗️ Technical Architecture](#technical-architecture)
  - [Core Classes](#core-classes)
  - [Data Models](#data-models)
  - [Database Schema](#database-schema)
- [📄 Output Formats](#output-formats)
  - [Console Output](#console-output)
  - [JSON Output](#json-output)
  - [HTML Output](#html-output)
- [🎯 Use Cases](#use-cases)
- [🔐 Security Considerations](#security-considerations)
- [💡 Advanced Usage](#advanced-usage)
- [🧪 Testing & Quality](#testing--quality)
- [🎓 Skills Demonstrated](#skills-demonstrated)
- [🔍 Troubleshooting](#troubleshooting)
- [🚀 Future Enhancements](#future-enhancements)
- [💻 Development](#development)
- [📜 License](#license)
- [💬 Support](#support)
- [🔄 Changelog](#changelog)

---

<a id="overview"></a>
## 🛡️ Overview

Guardian is a Python-based File Integrity Monitor that creates baselines of your file system and continuously monitors for unauthorized changes. It's designed to detect potential security breaches, malware infections, and unauthorized system modifications by tracking file changes at the cryptographic hash level.

It creates cryptographic baselines of your file system and continuously monitors for unauthorized changes. It's designed to detect potential security breaches, malware infections, and unauthorized system modifications by tracking file changes at the hash level.

---

<a id="features"></a>
## 🚀 Features

<a id="core-functionality"></a>
### Core Functionality
- ✅ **Baseline Creation**: Create cryptographic baselines of directories using SHA256, SHA1, and MD5 hashes  
- ✅ **Integrity Checking**: Compare current file states against established baselines  
- ✅ **Change Detection**: Identify added, modified, and removed files  
- ✅ **Comprehensive Reporting**: Generate detailed reports in multiple formats (console, JSON, HTML)

<a id="advanced-features"></a>
### Advanced Features
- ✅ **Configurable Exclusions**: Exclude temporary files, logs, and other non-critical files  
- ✅ **Multiple Hash Algorithms**: Support for SHA256, SHA1, and MD5 for flexibility  
- ✅ **SQLite Database**: Efficient storage and retrieval of baseline data  
- ✅ **Comprehensive Logging**: Detailed logging with configurable levels  
- ✅ **Performance Optimization**: Chunked file reading for large files  
- ✅ **Critical File Monitoring**: Special alerts for critical system files  
- ✅ **Change History**: Track all changes over time in the database  
- ✅ **Cross-Platform**: Works on Windows, Linux, and macOS  
- ✅ **Zero Dependencies**: Uses only the Python standard library

---

<a id="installation"></a>
## ⚙️ Installation

<a id="prerequisites"></a>
### Prerequisites
- Python 3.7 or higher  
- Standard library modules (no external dependencies required)

<a id="quick-start"></a>
### Quick Start
1. Clone or download the Guardian files.  
2. Ensure Python 3.7+ is installed.  
3. Run Guardian with your desired options:

```bash
# Create a baseline
python guardian.py --baseline /etc --name "system_config_baseline"

# Check integrity
python guardian.py --check /etc
```

---

<a id="usage"></a>
## 🎮 Usage

<a id="command-line-interface"></a>
### Command Line Interface

<a id="create-a-baseline"></a>
#### Create a Baseline

```bash
python guardian.py --baseline <path> [--name <baseline_name>]
```

**Examples:**

```bash
# Create baseline for system configuration
python guardian.py --baseline /etc --name "system_config_baseline"

# Create baseline for web server files
python guardian.py --baseline /var/www --name "web_files_baseline"

# Create baseline with auto-generated name
python guardian.py --baseline /home/user/documents
```

<a id="check-integrity"></a>
#### Check Integrity

```bash
python guardian.py --check <path> [--output <format>] [--save-report] [--fail-on-changes]
```

**Examples:**

```bash
# Basic integrity check
python guardian.py --check /etc

# Check with JSON output
python guardian.py --check /etc --output json

# Check and save report to file
python guardian.py --check /etc --save-report

# Check and exit with error code if changes detected
python guardian.py --check /etc --fail-on-changes
```

<a id="programmatic-usage"></a>
### Programmatic Usage

Guardian can also be imported and used directly in other Python scripts.

```python
from guardian import Guardian

# Initialize Guardian (loads from guardian.conf)
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

<a id="configuration"></a>
## 🔧 Configuration

Guardian uses a configuration file (guardian.conf) for persistent settings:

```ini
[DEFAULT]
# Database file for storing baselines
database_file = guardian_baseline.db

# Logging configuration
log_file = guardian.log
log_level = INFO

# Hash algorithms to use (comma-separated)
hash_algorithms = sha256,sha1,md5

# File patterns to exclude from scanning
exclude_patterns = *.tmp,*.log,*.cache,*.swp,.DS_Store,Thumbs.db

# Maximum file size to scan
max_file_size = 100MB

[PATHS]
# Paths to monitor
monitor_paths = /etc,/var/log,/home

# Paths to exclude from monitoring
exclude_paths = /proc,/sys,/dev,/tmp

[REPORTING]
# Output format: console, json, html
output_format = console

# Generate detailed reports
detailed_report = true

# Alert on critical file changes
alert_on_critical = true

# Critical files that should trigger alerts
critical_paths = /etc/passwd,/etc/shadow,/etc/sudoers
```

---

<a id="project-structure"></a>
## 📁 Project Structure

```
Guardian/
├── guardian.py           # Main application (500+ lines)
├── guardian.conf         # Configuration file
├── test_guardian.py      # Comprehensive test suite (400+ lines)
├── example_usage.py      # Interactive demonstration script
├── setup.py              # Setup and installation script
├── requirements.txt      # Dependencies (minimal - uses only stdlib)
├── README.md             # This documentation
└── monitor.sh            # Sample monitoring script (created by setup)
```

---

<a id="technical-architecture"></a>
## 🏗️ Technical Architecture

<a id="core-classes"></a>
### Core Classes

- **Guardian**: Main application controller  
- **GuardianConfig**: Configuration management (INI parsing and validation)  
- **GuardianDatabase**: SQLite database operations and schema management  
- **GuardianScanner**: File system scanning and cryptographic hashing  
- **GuardianReporter**: Report generation in multiple formats (console, JSON, HTML)

<a id="data-models"></a>
### Data Models

- **FileInfo**: Dataclass for file metadata and hash information  
- **ChangeReport**: Dataclass for change detection results  
- **ChangeType**: Enum for change types (ADDED, MODIFIED, REMOVED)

<a id="database-schema"></a>
### Database Schema

- **baselines**: Stores baseline metadata (ID, name, path, timestamp)  
- **files**: Stores all file information (path, hashes, size, mtime) linked to a baseline  
- **change_history**: Tracks all detected changes over time for auditing

---

<a id="output-formats"></a>
## 📄 Output Formats

<a id="console-output"></a>
### Console Output

```
============================================================
GUARDIAN FILE INTEGRITY MONITOR - CHANGE REPORT
============================================================
Scan completed at: 2024-01-15 14:30:25
Total changes detected: 3

[ADDED] (1 files)
----------------------------------------
  /etc/new_config.conf

[MODIFIED] (1 files)
----------------------------------------
  /etc/passwd
    Old hash: 5d41402abc4b2a76b9719d911017c592...
    New hash: 098f6bcd4621d373cade4e832627b4f6...
    Size: 1024 -> 2048 bytes

[REMOVED] (1 files)
----------------------------------------
  /etc/old_config.conf
```

<a id="json-output"></a>
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

<a id="html-output"></a>
### HTML Output

Generates a complete, styled HTML report suitable for email or web display.

---

<a id="use-cases"></a>
## 🎯 Use Cases

### System Administration

- Monitor critical system directories (/etc, /usr/bin, /sbin)  
- Detect unauthorized configuration changes  
- Track system file modifications

### Web Server Security

- Monitor web application files  
- Detect unauthorized code changes  
- Track configuration file modifications

### Development Environments

- Monitor source code repositories  
- Detect unauthorized code changes  
- Track build artifact modifications

### Compliance and Auditing

- Generate compliance reports  
- Track system changes for audit trails  
- Monitor critical business files

---

<a id="security-considerations"></a>
## 🔐 Security Considerations

### What Guardian Detects

- File Modifications: Changes to existing files (content, permissions, timestamps)  
- File Additions: New files added to monitored directories  
- File Deletions: Files removed from monitored directories  
- Permission Changes: Changes to file permissions and ownership

### What Guardian Does NOT Detect

- In-Memory Changes: Modifications that don't touch the file system  
- Network Activity: Network-based attacks or data exfiltration  
- Process Monitoring: Running processes or system calls  
- Registry Changes: Windows registry modifications (Windows-specific)

### Best Practices

- Regular Baselines: Create fresh baselines after system updates  
- Critical Paths: Focus monitoring on critical system directories  
- Exclusion Lists: Properly configure exclusions to reduce noise  
- Regular Checks: Schedule regular integrity checks  
- Secure Storage: Protect baseline databases and configuration files

---

<a id="advanced-usage"></a>
## 💡 Advanced Usage

Automated Monitoring

Create a simple monitoring script (monitor.sh):

```bash
#!/bin/bash
# monitor.sh - Automated Guardian monitoring

BASELINE_PATH="/etc"
REPORT_DIR="/var/log/guardian"

# Create baseline if it doesn't exist
if [ ! -f "guardian_baseline.db" ]; then
    python guardian.py --baseline "$BASELINE_PATH" --name "auto_baseline_$(date +%Y%m%d)"
fi

# Check integrity and save report
python guardian.py --check "$BASELINE_PATH" --save-report --output json

# Move report to log directory
mv guardian_report_*.txt "$REPORT_DIR/"
```

Integration with Monitoring Systems

Guardian can be integrated with existing monitoring systems using the --fail-on-changes flag:

```bash
# Check integrity and get exit code
python guardian.py --check /etc --fail-on-changes
if [ $? -ne 0 ]; then
    # Send alert to monitoring system
    curl -X POST "https://monitoring.example.com/alerts" \
         -H "Content-Type: application/json" \
         -d '{"alert": "File integrity violation detected"}'
fi
```

---

<a id="testing--quality"></a>
## 🧪 Testing & Quality

- Comprehensive Test Suite: 7 test classes (test_guardian.py) covering all functionality  
- Integration Tests: Full workflow testing from baseline creation to change detection  
- Error Handling: Robust error handling and graceful degradation  
- Cross-Platform Compatibility: Tested on Windows with proper encoding handling  
- No External Dependencies: Uses only Python standard library

---

<a id="skills-demonstrated"></a>
## 🎓 Skills Demonstrated

### Cybersecurity Concepts

- File Integrity Monitoring: Core HIDS functionality  
- Cryptographic Hashing: SHA256, SHA1, MD5 implementation  
- System Auditing: Comprehensive change tracking  
- Security Monitoring: Proactive threat detection

### Python Programming

- Object-Oriented Design: Clean class architecture with separation of concerns  
- Database Management: SQLite integration with proper schema design  
- Configuration Management: INI file parsing and validation  
- Logging Systems: Professional logging with multiple levels  
- Command-Line Interfaces: Full argparse implementation  
- Data Structures: Dataclasses, enums, and type hints  
- Error Handling: Comprehensive exception handling  
- File System Operations: Recursive directory scanning and file processing

### Software Engineering

- Modular Architecture: Separated concerns across multiple classes  
- Configuration-Driven: Flexible configuration system  
- Extensible Design: Easy to add new features and output formats  
- Documentation: Complete documentation and examples  
- Testing: Comprehensive test coverage

---

<a id="troubleshooting"></a>
## 🔍 Troubleshooting

Common Issues

**"No baseline found for path"**

- Cause: No baseline has been created for the specified path  
- Solution: Create a baseline first using --baseline option

**"Permission denied" errors**

- Cause: Insufficient permissions to read files or directories  
- Solution: Run Guardian with appropriate privileges (e.g., sudo)

**Large file exclusions**

- Cause: Files exceed the configured maximum size limit  
- Solution: Adjust max_file_size in configuration or exclude large files

**Performance issues with large directories**

- Cause: Scanning very large directory trees  
- Solution: Use exclusion patterns to reduce scan scope

Log Analysis

Guardian creates detailed logs in the configured log file. Common log entries:

```
2024-01-15 14:30:25,123 - guardian - INFO - Creating baseline 'system_config' for path: /etc
2024-01-15 14:30:25,456 - guardian - INFO - Scanned 1,234 files
2024-01-15 14:30:25,789 - guardian - INFO - Baseline created successfully. ID: 1, Files: 1,234
```

---

<a id="future-enhancements"></a>
## 🚀 Future Enhancements

The architecture supports easy addition of:

- Email/SMS alerts for critical changes  
- Webhook integrations for monitoring systems  
- Real-time monitoring with file system watchers  
- Web-based dashboard  
- Advanced filtering and correlation rules  
- Integration with SIEM systems

---

<a id="development"></a>
## 💻 Development

Running Tests

```bash
python test_guardian.py
```

Contributing

- Fork the repository  
- Create a feature branch  
- Add tests for new functionality  
- Ensure all tests pass  
- Submit a pull request

---

<a id="license"></a>
## 📜 License

This project is open source and available under the MIT License.

---

<a id="support"></a>
## 💬 Support

For issues, questions, or contributions:

- Check the troubleshooting section  
- Review the test cases for usage examples  
- Create an issue with detailed information

---

<a id="changelog"></a>
## 🔄 Changelog

### Version 1.0.0
- Initial release
- Core FIM functionality
- Multiple output formats
- SQLite database storage
- Comprehensive configuration system
- Full test coverage
