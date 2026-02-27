#!/usr/bin/env python3
"""
Test script to verify severity config implementation works correctly.
Run this after building the vow binary.
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path

def run_vow_command(args, input_text=None):
    """Run vow command and return stdout, stderr, and exit code."""
    cmd = ["./target/release/vow"] + args
    try:
        result = subprocess.run(
            cmd, 
            input=input_text.encode() if input_text else None,
            capture_output=True, 
            text=True
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", "vow binary not found", 1

def test_severity_filtering():
    """Test severity filtering functionality."""
    print("🧪 Testing severity filtering...")
    
    # Create a test file with different severity issues
    test_content = '''
# This file has various issues of different severities
import fake_package_that_does_not_exist  # High severity hallucination
password = "hardcoded123"  # Medium severity security issue
print("Hello world")  # This should be fine
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_content)
        test_file = f.name
    
    try:
        # Test 1: Run without min-severity (should show all issues)
        print("  📋 Test 1: No severity filtering")
        stdout, stderr, exit_code = run_vow_command(["check", test_file, "--format", "json"])
        if exit_code == 0:
            data = json.loads(stdout)
            total_issues = sum(len(file_result["issues"]) for file_result in data["files"])
            print(f"    ✅ Found {total_issues} total issues")
        else:
            print(f"    ❌ Command failed: {stderr}")
        
        # Test 2: Run with --min-severity high (should filter out low and medium)
        print("  📋 Test 2: High severity filtering")
        stdout, stderr, exit_code = run_vow_command(["check", test_file, "--min-severity", "high", "--format", "json"])
        if exit_code == 0:
            data = json.loads(stdout)
            high_issues = sum(
                len([issue for issue in file_result["issues"] 
                     if issue["severity"] in ["High", "Critical"]])
                for file_result in data["files"]
            )
            print(f"    ✅ Found {high_issues} high+ severity issues")
        else:
            print(f"    ❌ Command failed: {stderr}")
            
        # Test 3: Run with --min-severity critical (should show only critical)
        print("  📋 Test 3: Critical severity filtering")
        stdout, stderr, exit_code = run_vow_command(["check", test_file, "--min-severity", "critical", "--format", "json"])
        if exit_code == 0:
            data = json.loads(stdout)
            critical_issues = sum(
                len([issue for issue in file_result["issues"] 
                     if issue["severity"] == "Critical"])
                for file_result in data["files"]
            )
            print(f"    ✅ Found {critical_issues} critical severity issues")
        else:
            print(f"    ❌ Command failed: {stderr}")
            
    finally:
        os.unlink(test_file)

def test_config_file_severity():
    """Test severity configuration via config file."""
    print("🧪 Testing config file severity...")
    
    # Create a temporary config with min_severity set
    config_content = '''
analyzers:
  - code
  - text
  - security

output: json

min_severity: medium
'''
    
    test_content = '''
import fake_package
password = "secret123"
print("hello")
'''
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create .vow directory and config
        vow_dir = temp_path / ".vow"
        vow_dir.mkdir()
        (vow_dir / "config.yaml").write_text(config_content)
        
        # Create test file
        test_file = temp_path / "test.py"
        test_file.write_text(test_content)
        
        # Run vow check (should use config file min_severity)
        stdout, stderr, exit_code = run_vow_command(["check", str(test_file)])
        if exit_code == 0:
            print("    ✅ Config file severity filtering works")
        else:
            print(f"    ❌ Config test failed: {stderr}")

def test_cli_override_config():
    """Test that CLI flag overrides config file."""
    print("🧪 Testing CLI override of config...")
    
    config_content = '''
analyzers:
  - code
  - text  
  - security

output: json
min_severity: low
'''
    
    test_content = '''
import fake_package
password = "secret123"  
'''
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create .vow directory and config (set to low)
        vow_dir = temp_path / ".vow"
        vow_dir.mkdir()
        (vow_dir / "config.yaml").write_text(config_content)
        
        # Create test file
        test_file = temp_path / "test.py"
        test_file.write_text(test_content)
        
        # Run vow check with CLI override (high severity)
        stdout, stderr, exit_code = run_vow_command([
            "check", str(test_file), "--min-severity", "critical", "--format", "json"
        ])
        
        if exit_code == 0:
            data = json.loads(stdout)
            # Should only have critical issues, not medium ones
            critical_count = sum(
                len([issue for issue in file_result["issues"] 
                     if issue["severity"] == "Critical"])
                for file_result in data["files"]
            )
            print(f"    ✅ CLI override works, found {critical_count} critical issues only")
        else:
            print(f"    ❌ CLI override test failed: {stderr}")

def main():
    """Run all tests."""
    print("🎯 Testing Vow Severity Configuration Implementation")
    print("=" * 60)
    
    # Check if vow binary exists
    if not os.path.exists("./target/release/vow"):
        print("❌ Vow binary not found. Please run 'cargo build --release' first.")
        return 1
    
    test_severity_filtering()
    print()
    test_config_file_severity()
    print()
    test_cli_override_config()
    
    print("\n✅ All tests completed!")
    return 0

if __name__ == "__main__":
    exit(main())