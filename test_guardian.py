#!/usr/bin/env python3
"""
Test suite for Guardian FIM system.
"""

import os
import sys
import tempfile
import shutil
import unittest
import sqlite3
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the current directory to the path so we can import guardian
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardian import (
    Guardian, GuardianConfig, GuardianDatabase, GuardianScanner, GuardianReporter,
    FileInfo, ChangeReport, ChangeType
)


class TestGuardianConfig(unittest.TestCase):
    """Test GuardianConfig class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_guardian.conf')
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_default_config(self):
        """Test default configuration values."""
        config = GuardianConfig(self.config_file)
        
        self.assertEqual(config.get('DEFAULT', 'database_file'), 'guardian_baseline.db')
        self.assertEqual(config.get('DEFAULT', 'log_level'), 'INFO')
        self.assertIn('sha256', config.get('DEFAULT', 'hash_algorithms'))
    
    def test_config_save_load(self):
        """Test saving and loading configuration."""
        config = GuardianConfig(self.config_file)
        config.save_config()
        
        # Create new config instance and verify it loads the saved config
        new_config = GuardianConfig(self.config_file)
        self.assertEqual(new_config.get('DEFAULT', 'database_file'), 'guardian_baseline.db')
    
    def test_get_list(self):
        """Test getting configuration values as lists."""
        config = GuardianConfig(self.config_file)
        patterns = config.get_list('DEFAULT', 'exclude_patterns')
        
        self.assertIsInstance(patterns, list)
        self.assertIn('*.tmp', patterns)


class TestGuardianDatabase(unittest.TestCase):
    """Test GuardianDatabase class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.temp_dir, 'test_guardian.db')
        self.db = GuardianDatabase(self.db_file)
    
    def tearDown(self):
        """Clean up test fixtures."""
        try:
            # Close any open database connections first
            if hasattr(self, 'db'):
                del self.db
            # Give Windows time to release file handles
            import time
            time.sleep(0.1)
            shutil.rmtree(self.temp_dir)
        except (PermissionError, OSError) as e:
            # On Windows, sometimes files are still locked
            # This is a known issue and doesn't affect functionality
            print(f"Warning: Could not clean up {self.temp_dir}: {e}")
            pass
    
    def test_database_initialization(self):
        """Test database initialization creates required tables."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Check if tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            self.assertIn('baselines', tables)
            self.assertIn('files', tables)
            self.assertIn('change_history', tables)
    
    def test_create_baseline(self):
        """Test creating a baseline."""
        # Create test files
        test_files = [
            FileInfo(
                path='/test/file1.txt',
                size=100,
                modified_time=1234567890.0,
                hash_sha256='abc123',
                hash_sha1='def456',
                hash_md5='ghi789',
                permissions='644'
            ),
            FileInfo(
                path='/test/file2.txt',
                size=200,
                modified_time=1234567891.0,
                hash_sha256='jkl012',
                hash_sha1='mno345',
                hash_md5='pqr678',
                permissions='755'
            )
        ]
        
        baseline_id = self.db.create_baseline('test_baseline', '/test', test_files)
        
        self.assertIsNotNone(baseline_id)
        
        # Verify baseline was created
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM baselines WHERE id = ?", (baseline_id,))
            baseline = cursor.fetchone()
            
            self.assertIsNotNone(baseline)
            self.assertEqual(baseline[1], 'test_baseline')  # name
            self.assertEqual(baseline[3], '/test')  # path
            self.assertEqual(baseline[4], 2)  # file_count
    
    def test_get_baseline_files(self):
        """Test retrieving baseline files."""
        # Create test baseline
        test_files = [
            FileInfo(
                path='/test/file1.txt',
                size=100,
                modified_time=1234567890.0,
                hash_sha256='abc123',
                hash_sha1='def456',
                hash_md5='ghi789',
                permissions='644'
            )
        ]
        
        baseline_id = self.db.create_baseline('test_baseline', '/test', test_files)
        files = self.db.get_baseline_files(baseline_id)
        
        self.assertEqual(len(files), 1)
        self.assertIn('/test/file1.txt', files)
        self.assertEqual(files['/test/file1.txt'].hash_sha256, 'abc123')


class TestGuardianScanner(unittest.TestCase):
    """Test GuardianScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_guardian.conf')
        
        # Create test configuration
        config = GuardianConfig(self.config_file)
        config.save_config()
        
        self.config = config
        self.scanner = GuardianScanner(self.config)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_should_exclude(self):
        """Test file exclusion logic."""
        # Test pattern exclusion
        self.assertTrue(self.scanner._should_exclude('/tmp/test.tmp'))
        self.assertTrue(self.scanner._should_exclude('/var/log/app.log'))
        
        # Test path exclusion
        self.assertTrue(self.scanner._should_exclude('/proc/cpuinfo'))
        self.assertTrue(self.scanner._should_exclude('/sys/kernel'))
        
        # Test files that should not be excluded
        self.assertFalse(self.scanner._should_exclude('/etc/passwd'))
        self.assertFalse(self.scanner._should_exclude('/home/user/document.txt'))
    
    def test_parse_size(self):
        """Test size parsing."""
        self.assertEqual(self.scanner._parse_size('1024B'), 1024)
        self.assertEqual(self.scanner._parse_size('1KB'), 1024)
        self.assertEqual(self.scanner._parse_size('1MB'), 1024 * 1024)
        self.assertEqual(self.scanner._parse_size('1GB'), 1024 * 1024 * 1024)
    
    def test_scan_directory(self):
        """Test directory scanning."""
        # Create test directory structure
        test_dir = os.path.join(self.temp_dir, 'test_scan')
        os.makedirs(test_dir)
        
        # Create test files
        test_file1 = os.path.join(test_dir, 'file1.txt')
        test_file2 = os.path.join(test_dir, 'file2.txt')
        
        with open(test_file1, 'w') as f:
            f.write('Hello, World!')
        
        with open(test_file2, 'w') as f:
            f.write('Test content')
        
        # Scan directory
        files = self.scanner.scan_directory(test_dir)
        
        self.assertEqual(len(files), 2)
        
        # Verify file information
        file_paths = [f.path for f in files]
        self.assertIn(test_file1, file_paths)
        self.assertIn(test_file2, file_paths)
        
        # Verify hashes are calculated
        for file_info in files:
            self.assertNotEqual(file_info.hash_sha256, '')
            self.assertNotEqual(file_info.hash_sha1, '')
            self.assertNotEqual(file_info.hash_md5, '')


class TestGuardianReporter(unittest.TestCase):
    """Test GuardianReporter class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_guardian.conf')
        
        config = GuardianConfig(self.config_file)
        config.save_config()
        
        self.config = config
        self.reporter = GuardianReporter(self.config)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_console_report(self):
        """Test console report generation."""
        changes = [
            ChangeReport(
                change_type=ChangeType.ADDED,
                file_path='/test/new_file.txt',
                new_hash='abc123'
            ),
            ChangeReport(
                change_type=ChangeType.MODIFIED,
                file_path='/test/modified_file.txt',
                old_hash='def456',
                new_hash='ghi789',
                old_size=100,
                new_size=200
            )
        ]
        
        report = self.reporter._generate_console_report(changes)
        
        self.assertIn('GUARDIAN FILE INTEGRITY MONITOR', report)
        self.assertIn('[ADDED]', report)
        self.assertIn('[MODIFIED]', report)
        self.assertIn('/test/new_file.txt', report)
        self.assertIn('/test/modified_file.txt', report)
    
    def test_json_report(self):
        """Test JSON report generation."""
        changes = [
            ChangeReport(
                change_type=ChangeType.ADDED,
                file_path='/test/new_file.txt',
                new_hash='abc123'
            )
        ]
        
        report = self.reporter._generate_json_report(changes)
        
        # Should be valid JSON
        import json
        data = json.loads(report)
        
        self.assertEqual(data['total_changes'], 1)
        self.assertEqual(len(data['changes']), 1)
        self.assertEqual(data['changes'][0]['change_type'], 'ADDED')
    
    def test_html_report(self):
        """Test HTML report generation."""
        changes = [
            ChangeReport(
                change_type=ChangeType.ADDED,
                file_path='/test/new_file.txt',
                new_hash='abc123'
            )
        ]
        
        report = self.reporter._generate_html_report(changes)
        
        self.assertIn('<html>', report)
        self.assertIn('<title>Guardian FIM Report</title>', report)
        self.assertIn('/test/new_file.txt', report)


class TestGuardianIntegration(unittest.TestCase):
    """Integration tests for the complete Guardian system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_guardian.conf')
        
        # Create test configuration
        config = GuardianConfig(self.config_file)
        config.save_config()
        
        self.guardian = Guardian(self.config_file)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_full_workflow(self):
        """Test complete baseline creation and integrity check workflow."""
        # Create test directory structure
        test_dir = os.path.join(self.temp_dir, 'test_monitor')
        os.makedirs(test_dir)
        
        # Create initial files
        file1 = os.path.join(test_dir, 'file1.txt')
        file2 = os.path.join(test_dir, 'file2.txt')
        
        with open(file1, 'w') as f:
            f.write('Initial content 1')
        
        with open(file2, 'w') as f:
            f.write('Initial content 2')
        
        # Create baseline
        baseline_id = self.guardian.create_baseline(test_dir, 'test_baseline')
        self.assertIsNotNone(baseline_id)
        
        # Check integrity (should be no changes)
        changes = self.guardian.check_integrity(test_dir)
        self.assertEqual(len(changes), 0)
        
        # Modify a file
        with open(file1, 'w') as f:
            f.write('Modified content 1')
        
        # Add a new file
        file3 = os.path.join(test_dir, 'file3.txt')
        with open(file3, 'w') as f:
            f.write('New file content')
        
        # Remove a file
        os.remove(file2)
        
        # Check integrity again
        changes = self.guardian.check_integrity(test_dir)
        
        # Should detect 3 changes: 1 modified, 1 added, 1 removed
        self.assertEqual(len(changes), 3)
        
        change_types = [change.change_type for change in changes]
        self.assertIn(ChangeType.MODIFIED, change_types)
        self.assertIn(ChangeType.ADDED, change_types)
        self.assertIn(ChangeType.REMOVED, change_types)


class TestFileInfo(unittest.TestCase):
    """Test FileInfo dataclass."""
    
    def test_file_info_creation(self):
        """Test FileInfo object creation."""
        file_info = FileInfo(
            path='/test/file.txt',
            size=1024,
            modified_time=1234567890.0,
            hash_sha256='abc123',
            hash_sha1='def456',
            hash_md5='ghi789',
            permissions='644'
        )
        
        self.assertEqual(file_info.path, '/test/file.txt')
        self.assertEqual(file_info.size, 1024)
        self.assertEqual(file_info.hash_sha256, 'abc123')


class TestChangeReport(unittest.TestCase):
    """Test ChangeReport dataclass."""
    
    def test_change_report_creation(self):
        """Test ChangeReport object creation."""
        change = ChangeReport(
            change_type=ChangeType.MODIFIED,
            file_path='/test/file.txt',
            old_hash='abc123',
            new_hash='def456'
        )
        
        self.assertEqual(change.change_type, ChangeType.MODIFIED)
        self.assertEqual(change.file_path, '/test/file.txt')
        self.assertEqual(change.old_hash, 'abc123')
        self.assertEqual(change.new_hash, 'def456')
        self.assertIsNotNone(change.timestamp)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestGuardianConfig,
        TestGuardianDatabase,
        TestGuardianScanner,
        TestGuardianReporter,
        TestGuardianIntegration,
        TestFileInfo,
        TestChangeReport
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
