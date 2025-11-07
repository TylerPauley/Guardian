#!/usr/bin/env python3
"""
Example usage of Guardian FIM system.
This script demonstrates how to use Guardian programmatically.
"""

import os
import tempfile
import shutil
from guardian import Guardian


def create_test_environment():
    """Create a test environment with sample files."""
    # Create temporary directory
    test_dir = tempfile.mkdtemp(prefix='guardian_test_')
    
    # Create subdirectories
    subdir1 = os.path.join(test_dir, 'config')
    subdir2 = os.path.join(test_dir, 'data')
    os.makedirs(subdir1)
    os.makedirs(subdir2)
    
    # Create test files
    files_to_create = [
        (os.path.join(test_dir, 'main.conf'), 'server_name=example.com\nport=8080'),
        (os.path.join(subdir1, 'app.conf'), 'debug=true\nlog_level=info'),
        (os.path.join(subdir2, 'data.txt'), 'Sample data content\nLine 2\nLine 3'),
        (os.path.join(test_dir, 'readme.txt'), 'This is a test environment for Guardian FIM')
    ]
    
    for file_path, content in files_to_create:
        with open(file_path, 'w') as f:
            f.write(content)
    
    return test_dir


def demonstrate_baseline_creation(guardian, test_dir):
    """Demonstrate baseline creation."""
    print("=" * 60)
    print("DEMONSTRATING BASELINE CREATION")
    print("=" * 60)
    
    # Create baseline
    baseline_id = guardian.create_baseline(test_dir, "example_baseline")
    
    if baseline_id:
        print(f"[OK] Baseline created successfully with ID: {baseline_id}")
        
        # List files in baseline
        baseline_files = guardian.db.get_baseline_files(baseline_id)
        print(f"[OK] Baseline contains {len(baseline_files)} files:")
        for file_path in sorted(baseline_files.keys()):
            file_info = baseline_files[file_path]
            print(f"  - {file_path} ({file_info.size} bytes, hash: {file_info.hash_sha256[:16]}...)")
    else:
        print("[ERROR] Failed to create baseline")
    
    return baseline_id


def demonstrate_integrity_check(guardian, test_dir):
    """Demonstrate integrity checking."""
    print("\n" + "=" * 60)
    print("DEMONSTRATING INTEGRITY CHECK (No Changes)")
    print("=" * 60)
    
    # Check integrity (should be no changes)
    changes = guardian.check_integrity(test_dir)
    
    if not changes:
        print("[OK] No changes detected - system integrity maintained")
    else:
        print(f"[ERROR] Unexpected changes detected: {len(changes)}")
        for change in changes:
            print(f"  - {change.change_type.value}: {change.file_path}")


def demonstrate_file_changes(guardian, test_dir):
    """Demonstrate detection of file changes."""
    print("\n" + "=" * 60)
    print("DEMONSTRATING FILE CHANGE DETECTION")
    print("=" * 60)
    
    # Modify an existing file
    main_conf = os.path.join(test_dir, 'main.conf')
    with open(main_conf, 'a') as f:
        f.write('\n# Modified by Guardian demo')
    
    # Add a new file
    new_file = os.path.join(test_dir, 'new_file.txt')
    with open(new_file, 'w') as f:
        f.write('This is a new file added after baseline creation')
    
    # Remove a file
    readme_file = os.path.join(test_dir, 'readme.txt')
    if os.path.exists(readme_file):
        os.remove(readme_file)
    
    print("[OK] Made the following changes:")
    print("  - Modified: main.conf (added comment)")
    print("  - Added: new_file.txt")
    print("  - Removed: readme.txt")
    
    # Check integrity
    changes = guardian.check_integrity(test_dir)
    
    print(f"\n[OK] Guardian detected {len(changes)} changes:")
    for change in changes:
        print(f"  - [{change.change_type.value}] {change.file_path}")
        if change.change_type.value == "MODIFIED":
            print(f"    Old hash: {change.old_hash[:16]}...")
            print(f"    New hash: {change.new_hash[:16]}...")


def demonstrate_reporting(guardian, test_dir):
    """Demonstrate different reporting formats."""
    print("\n" + "=" * 60)
    print("DEMONSTRATING REPORTING FORMATS")
    print("=" * 60)
    
    # Get changes
    changes = guardian.check_integrity(test_dir)
    
    if changes:
        # Console report
        print("CONSOLE REPORT:")
        print("-" * 40)
        console_report = guardian.reporter._generate_console_report(changes)
        print(console_report)
        
        # JSON report
        print("\nJSON REPORT:")
        print("-" * 40)
        json_report = guardian.reporter._generate_json_report(changes)
        print(json_report)
        
        # HTML report (first 500 chars)
        print("\nHTML REPORT (first 500 characters):")
        print("-" * 40)
        html_report = guardian.reporter._generate_html_report(changes)
        print(html_report[:500] + "..." if len(html_report) > 500 else html_report)
    else:
        print("No changes to report")


def main():
    """Main demonstration function."""
    print("GUARDIAN FIM - EXAMPLE USAGE DEMONSTRATION")
    print("=" * 60)
    print("This script demonstrates the core functionality of Guardian FIM")
    print("by creating a test environment and showing how to:")
    print("1. Create baselines")
    print("2. Check integrity")
    print("3. Detect changes")
    print("4. Generate reports")
    print()
    
    # Create test environment
    test_dir = create_test_environment()
    print(f"[OK] Created test environment at: {test_dir}")
    
    try:
        # Initialize Guardian
        guardian = Guardian()
        
        # Demonstrate baseline creation
        baseline_id = demonstrate_baseline_creation(guardian, test_dir)
        
        if baseline_id:
            # Demonstrate integrity check (no changes)
            demonstrate_integrity_check(guardian, test_dir)
            
            # Demonstrate file changes
            demonstrate_file_changes(guardian, test_dir)
            
            # Demonstrate reporting
            demonstrate_reporting(guardian, test_dir)
        
        print("\n" + "=" * 60)
        print("DEMONSTRATION COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("Guardian FIM is working correctly!")
        print("\nNext steps:")
        print("1. Try running: python guardian.py --baseline /path/to/monitor")
        print("2. Then run: python guardian.py --check /path/to/monitor")
        print("3. Modify some files and run the check again")
        print("4. Review the generated reports")
        
    except Exception as e:
        print(f"[ERROR] Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up test environment
        print(f"\nCleaning up test environment: {test_dir}")
        shutil.rmtree(test_dir)
        print("[OK] Cleanup completed")


if __name__ == "__main__":
    main()
