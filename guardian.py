#!/usr/bin/env python3
"""
Guardian - File Integrity Monitor (FIM)
A comprehensive host-based intrusion detection system for monitoring file system changes.

Author: Guardian FIM System
Version: 1.0.0
"""

import os
import sys
import hashlib
import sqlite3
import json
import argparse
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
import configparser
from dataclasses import dataclass, asdict
from enum import Enum


class ChangeType(Enum):
    """Types of file changes detected."""
    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    REMOVED = "REMOVED"
    UNCHANGED = "UNCHANGED"


@dataclass
class FileInfo:
    """Information about a file for integrity monitoring."""
    path: str
    size: int
    modified_time: float
    hash_sha256: str
    hash_sha1: str
    hash_md5: str
    permissions: str
    inode: Optional[int] = None


@dataclass
class ChangeReport:
    """Report of changes detected during integrity check."""
    change_type: ChangeType
    file_path: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    old_size: Optional[int] = None
    new_size: Optional[int] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class GuardianConfig:
    """Configuration management for Guardian FIM."""
    
    def __init__(self, config_file: str = "guardian.conf"):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_defaults()
        self.load_config()
    
    def load_defaults(self):
        """Load default configuration values."""
        self.config['DEFAULT'] = {
            'database_file': 'guardian_baseline.db',
            'log_file': 'guardian.log',
            'log_level': 'INFO',
            'hash_algorithms': 'sha256,sha1,md5',
            'exclude_patterns': '*.tmp,*.log,*.cache,*.swp,.DS_Store,Thumbs.db',
            'max_file_size': '100MB',
            'scan_timeout': '300'
        }
        
        self.config['PATHS'] = {
            'monitor_paths': '/etc,/var/log,/home',
            'exclude_paths': '/proc,/sys,/dev,/tmp'
        }
        
        self.config['REPORTING'] = {
            'output_format': 'console',
            'detailed_report': 'true',
            'alert_on_critical': 'true',
            'critical_paths': '/etc/passwd,/etc/shadow,/etc/sudoers'
        }
    
    def load_config(self):
        """Load configuration from file if it exists."""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
    
    def save_config(self):
        """Save current configuration to file."""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def get(self, section: str, key: str, fallback: str = None) -> str:
        """Get configuration value."""
        return self.config.get(section, key, fallback=fallback)
    
    def get_list(self, section: str, key: str) -> List[str]:
        """Get configuration value as a list."""
        value = self.get(section, key, '')
        return [item.strip() for item in value.split(',') if item.strip()]


class GuardianDatabase:
    """Database management for Guardian FIM baseline storage."""
    
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Create baseline table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    path TEXT NOT NULL,
                    file_count INTEGER,
                    total_size INTEGER
                )
            ''')
            
            # Create files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    baseline_id INTEGER,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    modified_time REAL,
                    hash_sha256 TEXT,
                    hash_sha1 TEXT,
                    hash_md5 TEXT,
                    permissions TEXT,
                    inode INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (baseline_id) REFERENCES baselines (id)
                )
            ''')
            
            # Create change history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS change_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    baseline_id INTEGER,
                    change_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    old_size INTEGER,
                    new_size INTEGER,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (baseline_id) REFERENCES baselines (id)
                )
            ''')
            
            conn.commit()
    
    def create_baseline(self, name: str, path: str, files: List[FileInfo]) -> int:
        """Create a new baseline and store file information."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Calculate total size
            total_size = sum(f.size for f in files)
            
            # Insert baseline
            cursor.execute('''
                INSERT INTO baselines (name, path, file_count, total_size)
                VALUES (?, ?, ?, ?)
            ''', (name, path, len(files), total_size))
            
            baseline_id = cursor.lastrowid
            
            # Insert file information
            for file_info in files:
                cursor.execute('''
                    INSERT INTO files (baseline_id, file_path, file_size, modified_time,
                                     hash_sha256, hash_sha1, hash_md5, permissions, inode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (baseline_id, file_info.path, file_info.size, file_info.modified_time,
                      file_info.hash_sha256, file_info.hash_sha1, file_info.hash_md5,
                      file_info.permissions, file_info.inode))
            
            conn.commit()
            return baseline_id
    
    def get_baseline_files(self, baseline_id: int) -> Dict[str, FileInfo]:
        """Retrieve all files from a baseline."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path, file_size, modified_time, hash_sha256, hash_sha1,
                       hash_md5, permissions, inode
                FROM files WHERE baseline_id = ?
            ''', (baseline_id,))
            
            files = {}
            for row in cursor.fetchall():
                file_info = FileInfo(
                    path=row[0],
                    size=row[1],
                    modified_time=row[2],
                    hash_sha256=row[3],
                    hash_sha1=row[4],
                    hash_md5=row[5],
                    permissions=row[6],
                    inode=row[7]
                )
                files[row[0]] = file_info
            
            return files
    
    def get_latest_baseline(self, path: str) -> Optional[int]:
        """Get the latest baseline ID for a given path."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id FROM baselines WHERE path = ? ORDER BY created_at DESC LIMIT 1
            ''', (path,))
            
            result = cursor.fetchone()
            return result[0] if result else None
    
    def record_changes(self, baseline_id: int, changes: List[ChangeReport]):
        """Record detected changes in the database."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            for change in changes:
                cursor.execute('''
                    INSERT INTO change_history (baseline_id, change_type, file_path,
                                              old_hash, new_hash, old_size, new_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (baseline_id, change.change_type.value, change.file_path,
                      change.old_hash, change.new_hash, change.old_size, change.new_size))
            
            conn.commit()


class GuardianScanner:
    """File system scanner for Guardian FIM."""
    
    def __init__(self, config: GuardianConfig):
        self.config = config
        self.exclude_patterns = self._compile_exclude_patterns()
        self.max_file_size = self._parse_size(self.config.get('DEFAULT', 'max_file_size', '100MB'))
    
    def _compile_exclude_patterns(self) -> List[str]:
        """Compile exclude patterns for efficient matching."""
        patterns = self.config.get_list('DEFAULT', 'exclude_patterns')
        return patterns
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string (e.g., '100MB') to bytes."""
        size_str = size_str.upper().strip()
        # Check suffixes in order of length (longest first) to avoid partial matches
        multipliers = [('GB', 1024**3), ('MB', 1024**2), ('KB', 1024), ('B', 1)]
        
        for suffix, multiplier in multipliers:
            if size_str.endswith(suffix):
                number = size_str[:-len(suffix)]
                try:
                    return int(float(number) * multiplier)
                except ValueError:
                    # If parsing fails, return default
                    return 100 * 1024 * 1024  # 100MB default
        
        try:
            return int(size_str)  # Assume bytes if no suffix
        except ValueError:
            return 100 * 1024 * 1024  # 100MB default
    
    def _should_exclude(self, file_path: str) -> bool:
        """Check if a file should be excluded from scanning."""
        path = Path(file_path)
        
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if path.match(pattern) or path.name == pattern:
                return True
        
        # Check exclude paths
        exclude_paths = self.config.get_list('PATHS', 'exclude_paths')
        for exclude_path in exclude_paths:
            if file_path.startswith(exclude_path):
                return True
        
        return False
    
    def _calculate_hashes(self, file_path: str) -> Tuple[str, str, str]:
        """Calculate SHA256, SHA1, and MD5 hashes for a file."""
        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
                    sha1_hash.update(chunk)
                    md5_hash.update(chunk)
            
            return sha256_hash.hexdigest(), sha1_hash.hexdigest(), md5_hash.hexdigest()
        except (IOError, OSError) as e:
            logging.warning(f"Could not hash file {file_path}: {e}")
            return "", "", ""
    
    def scan_directory(self, directory: str) -> List[FileInfo]:
        """Recursively scan a directory and return file information."""
        files = []
        directory = os.path.abspath(directory)
        
        if not os.path.exists(directory):
            logging.error(f"Directory does not exist: {directory}")
            return files
        
        logging.info(f"Scanning directory: {directory}")
        
        try:
            for root, dirs, filenames in os.walk(directory):
                # Remove excluded directories from dirs list to prevent walking into them
                dirs[:] = [d for d in dirs if not self._should_exclude(os.path.join(root, d))]
                
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    
                    if self._should_exclude(file_path):
                        continue
                    
                    try:
                        stat_info = os.stat(file_path)
                        
                        # Skip if file is too large
                        if stat_info.st_size > self.max_file_size:
                            logging.warning(f"Skipping large file: {file_path} ({stat_info.st_size} bytes)")
                            continue
                        
                        # Calculate hashes
                        sha256, sha1, md5 = self._calculate_hashes(file_path)
                        
                        file_info = FileInfo(
                            path=file_path,
                            size=stat_info.st_size,
                            modified_time=stat_info.st_mtime,
                            hash_sha256=sha256,
                            hash_sha1=sha1,
                            hash_md5=md5,
                            permissions=oct(stat_info.st_mode)[-3:],
                            inode=stat_info.st_ino
                        )
                        
                        files.append(file_info)
                        
                    except (IOError, OSError) as e:
                        logging.warning(f"Could not process file {file_path}: {e}")
                        continue
        
        except (IOError, OSError) as e:
            logging.error(f"Error scanning directory {directory}: {e}")
        
        logging.info(f"Scanned {len(files)} files")
        return files


class GuardianReporter:
    """Report generation for Guardian FIM."""
    
    def __init__(self, config: GuardianConfig):
        self.config = config
    
    def generate_report(self, changes: List[ChangeReport], output_format: str = None) -> str:
        """Generate a report of detected changes."""
        if output_format is None:
            output_format = self.config.get('REPORTING', 'output_format', 'console')
        
        if output_format == 'json':
            return self._generate_json_report(changes)
        elif output_format == 'html':
            return self._generate_html_report(changes)
        else:
            return self._generate_console_report(changes)
    
    def _generate_console_report(self, changes: List[ChangeReport]) -> str:
        """Generate a console-formatted report."""
        if not changes:
            return "No changes detected. System integrity maintained."
        
        report = []
        report.append("=" * 60)
        report.append("GUARDIAN FILE INTEGRITY MONITOR - CHANGE REPORT")
        report.append("=" * 60)
        report.append(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total changes detected: {len(changes)}")
        report.append("")
        
        # Group changes by type
        by_type = {}
        for change in changes:
            if change.change_type not in by_type:
                by_type[change.change_type] = []
            by_type[change.change_type].append(change)
        
        for change_type in [ChangeType.ADDED, ChangeType.MODIFIED, ChangeType.REMOVED]:
            if change_type in by_type:
                report.append(f"[{change_type.value}] ({len(by_type[change_type])} files)")
                report.append("-" * 40)
                
                for change in by_type[change_type]:
                    report.append(f"  {change.file_path}")
                    if change.change_type == ChangeType.MODIFIED:
                        report.append(f"    Old hash: {change.old_hash[:16]}...")
                        report.append(f"    New hash: {change.new_hash[:16]}...")
                        if change.old_size != change.new_size:
                            report.append(f"    Size: {change.old_size} -> {change.new_size} bytes")
                
                report.append("")
        
        return "\n".join(report)
    
    def _generate_json_report(self, changes: List[ChangeReport]) -> str:
        """Generate a JSON-formatted report."""
        # Convert changes to JSON-serializable format
        json_changes = []
        for change in changes:
            change_dict = asdict(change)
            change_dict['change_type'] = change.change_type.value  # Convert enum to string
            json_changes.append(change_dict)
        
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "total_changes": len(changes),
            "changes": json_changes
        }
        return json.dumps(report_data, indent=2)
    
    def _generate_html_report(self, changes: List[ChangeReport]) -> str:
        """Generate an HTML-formatted report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Guardian FIM Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .change {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
                .added {{ border-left-color: #4CAF50; }}
                .modified {{ border-left-color: #FF9800; }}
                .removed {{ border-left-color: #F44336; }}
                .hash {{ font-family: monospace; font-size: 0.9em; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Guardian File Integrity Monitor</h1>
                <p>Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total changes: {len(changes)}</p>
            </div>
        """
        
        for change in changes:
            css_class = change.change_type.value.lower()
            html += f"""
            <div class="change {css_class}">
                <h3>[{change.change_type.value}] {change.file_path}</h3>
            """
            
            if change.change_type == ChangeType.MODIFIED:
                html += f"""
                <p class="hash">Old hash: {change.old_hash}</p>
                <p class="hash">New hash: {change.new_hash}</p>
                """
                if change.old_size != change.new_size:
                    html += f"<p>Size: {change.old_size} -> {change.new_size} bytes</p>"
            
            html += "</div>"
        
        html += "</body></html>"
        return html


class Guardian:
    """Main Guardian FIM class."""
    
    def __init__(self, config_file: str = "guardian.conf"):
        self.config = GuardianConfig(config_file)
        self.db = GuardianDatabase(self.config.get('DEFAULT', 'database_file'))
        self.scanner = GuardianScanner(self.config)
        self.reporter = GuardianReporter(self.config)
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.get('DEFAULT', 'log_level', 'INFO').upper())
        log_file = self.config.get('DEFAULT', 'log_file', 'guardian.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def create_baseline(self, path: str, name: str = None) -> int:
        """Create a new baseline for the specified path."""
        if name is None:
            name = f"baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logging.info(f"Creating baseline '{name}' for path: {path}")
        
        # Scan directory
        files = self.scanner.scan_directory(path)
        
        if not files:
            logging.warning(f"No files found in path: {path}")
            return None
        
        # Create baseline in database
        baseline_id = self.db.create_baseline(name, path, files)
        
        logging.info(f"Baseline created successfully. ID: {baseline_id}, Files: {len(files)}")
        return baseline_id
    
    def check_integrity(self, path: str, baseline_name: str = None) -> List[ChangeReport]:
        """Check integrity against a baseline."""
        # Get baseline
        baseline_id = self.db.get_latest_baseline(path)
        if baseline_id is None:
            logging.error(f"No baseline found for path: {path}")
            return []
        
        logging.info(f"Checking integrity for path: {path}")
        
        # Get baseline files
        baseline_files = self.db.get_baseline_files(baseline_id)
        
        # Scan current directory
        current_files = self.scanner.scan_directory(path)
        current_file_dict = {f.path: f for f in current_files}
        
        # Compare and detect changes
        changes = []
        
        # Check for modified and removed files
        for file_path, baseline_file in baseline_files.items():
            if file_path in current_file_dict:
                current_file = current_file_dict[file_path]
                if baseline_file.hash_sha256 != current_file.hash_sha256:
                    change = ChangeReport(
                        change_type=ChangeType.MODIFIED,
                        file_path=file_path,
                        old_hash=baseline_file.hash_sha256,
                        new_hash=current_file.hash_sha256,
                        old_size=baseline_file.size,
                        new_size=current_file.size
                    )
                    changes.append(change)
            else:
                change = ChangeReport(
                    change_type=ChangeType.REMOVED,
                    file_path=file_path,
                    old_hash=baseline_file.hash_sha256
                )
                changes.append(change)
        
        # Check for added files
        for file_path, current_file in current_file_dict.items():
            if file_path not in baseline_files:
                change = ChangeReport(
                    change_type=ChangeType.ADDED,
                    file_path=file_path,
                    new_hash=current_file.hash_sha256,
                    new_size=current_file.size
                )
                changes.append(change)
        
        # Record changes in database
        if changes:
            self.db.record_changes(baseline_id, changes)
        
        logging.info(f"Integrity check completed. Changes detected: {len(changes)}")
        return changes
    
    def run(self, args):
        """Main execution method."""
        if args.baseline:
            baseline_id = self.create_baseline(args.path, args.name)
            if baseline_id:
                print(f"Baseline created successfully with ID: {baseline_id}")
            else:
                print("Failed to create baseline")
                sys.exit(1)
        
        elif args.check:
            changes = self.check_integrity(args.path)
            if changes:
                report = self.reporter.generate_report(changes, args.output)
                print(report)
                
                # Save report to file if requested
                if args.save_report:
                    report_file = f"guardian_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(report_file, 'w') as f:
                        f.write(report)
                    print(f"Report saved to: {report_file}")
                
                # Exit with error code if changes detected
                if args.fail_on_changes:
                    sys.exit(1)
            else:
                print("No changes detected. System integrity maintained.")
        
        else:
            print("Please specify either --baseline or --check mode")
            sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Guardian - File Integrity Monitor (FIM)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a baseline
  python guardian.py --baseline /etc --name "system_config_baseline"
  
  # Check integrity
  python guardian.py --check /etc
  
  # Check with JSON output
  python guardian.py --check /etc --output json
  
  # Check and save report
  python guardian.py --check /etc --save-report
        """
    )
    
    parser.add_argument('--baseline', action='store_true',
                       help='Create a new baseline')
    parser.add_argument('--check', action='store_true',
                       help='Check integrity against baseline')
    parser.add_argument('--path',
                       help='Path to monitor')
    parser.add_argument('--name', 
                       help='Name for the baseline (optional)')
    parser.add_argument('--output', choices=['console', 'json', 'html'],
                       default='console', help='Output format for reports')
    parser.add_argument('--save-report', action='store_true',
                       help='Save report to file')
    parser.add_argument('--fail-on-changes', action='store_true',
                       help='Exit with error code if changes are detected')
    parser.add_argument('--config', default='guardian.conf',
                       help='Configuration file path')
    
    args = parser.parse_args()
    
    # Validate arguments
    if (args.baseline or args.check) and not args.path:
        parser.error("--path is required when using --baseline or --check")
    
    if not args.baseline and not args.check:
        parser.error("Please specify either --baseline or --check mode")
    
    # Initialize Guardian
    guardian = Guardian(args.config)
    
    # Run Guardian
    guardian.run(args)


if __name__ == "__main__":
    main()
