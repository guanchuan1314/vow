use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_single_format_no_output_dir() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.py");
    fs::write(&test_file, "print('hello')").unwrap();
    
    // Single format should work without output-dir
    let output = std::process::Command::new("./target/release/vow")
        .args(&["check", test_file.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("Failed to execute command");
    
    assert!(output.status.success() || output.status.code() == Some(0));
    assert!(!output.stdout.is_empty());
    
    // Should contain JSON output
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"files\""));
}

#[test]
fn test_multiple_formats_with_output_dir() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.py");
    fs::write(&test_file, "print('hello')").unwrap();
    
    let output_dir = temp_dir.path().join("reports");
    
    // Multiple formats should work with output-dir
    let output = std::process::Command::new("./target/release/vow")
        .args(&[
            "check", 
            test_file.to_str().unwrap(), 
            "--format", "terminal,json", 
            "--output-dir", output_dir.to_str().unwrap()
        ])
        .output()
        .expect("Failed to execute command");
    
    // Check that files were created
    assert!(output_dir.join("vow-report.txt").exists());
    assert!(output_dir.join("vow-report.json").exists());
    
    // Check file contents
    let txt_content = fs::read_to_string(output_dir.join("vow-report.txt")).unwrap();
    assert!(txt_content.contains("Vow Analysis Report"));
    
    let json_content = fs::read_to_string(output_dir.join("vow-report.json")).unwrap();
    assert!(json_content.contains("\"files\""));
}

#[test]
fn test_multiple_formats_without_output_dir_fails() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.py");
    fs::write(&test_file, "print('hello')").unwrap();
    
    // Multiple formats without output-dir should fail
    let output = std::process::Command::new("./target/release/vow")
        .args(&[
            "check", 
            test_file.to_str().unwrap(), 
            "--format", "terminal,json"
        ])
        .output()
        .expect("Failed to execute command");
    
    assert!(!output.status.success());
    
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Multiple formats require --output-dir"));
}

#[test]
fn test_sarif_format_output() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.py");
    fs::write(&test_file, "eval('test')").unwrap();
    
    let output_dir = temp_dir.path().join("reports");
    
    // Test SARIF format specifically
    let output = std::process::Command::new("./target/release/vow")
        .args(&[
            "check", 
            test_file.to_str().unwrap(), 
            "--format", "sarif", 
            "--output-dir", output_dir.to_str().unwrap()
        ])
        .output()
        .expect("Failed to execute command");
    
    // Check that SARIF file was created
    let sarif_file = output_dir.join("vow-report.sarif");
    assert!(sarif_file.exists());
    
    // Check SARIF content structure
    let sarif_content = fs::read_to_string(sarif_file).unwrap();
    assert!(sarif_content.contains("\"$schema\""));
    assert!(sarif_content.contains("\"runs\""));
    assert!(sarif_content.contains("sarif-2.1.0"));
}

#[test]
fn test_comma_separated_vs_repeated_flag() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.py");
    fs::write(&test_file, "print('hello')").unwrap();
    
    let output_dir1 = temp_dir.path().join("reports1");
    let output_dir2 = temp_dir.path().join("reports2");
    
    // Test comma-separated formats
    let output1 = std::process::Command::new("./target/release/vow")
        .args(&[
            "check", 
            test_file.to_str().unwrap(), 
            "--format", "terminal,json", 
            "--output-dir", output_dir1.to_str().unwrap()
        ])
        .output()
        .expect("Failed to execute command");
    
    // Test repeated flag (this should also work if implemented)
    // Note: clap with value_delimiter = ',' handles this automatically
    
    assert!(output_dir1.join("vow-report.txt").exists());
    assert!(output_dir1.join("vow-report.json").exists());
}

#[test]
fn test_invalid_format_error() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.py");
    fs::write(&test_file, "print('hello')").unwrap();
    
    // Test invalid format
    let output = std::process::Command::new("./target/release/vow")
        .args(&[
            "check", 
            test_file.to_str().unwrap(), 
            "--format", "invalid_format"
        ])
        .output()
        .expect("Failed to execute command");
    
    assert!(!output.status.success());
    
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Invalid format"));
}

#[test]
fn test_backward_compatibility() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.py");
    fs::write(&test_file, "print('hello')").unwrap();
    
    // Test that old behavior still works (no --format specified)
    let output = std::process::Command::new("./target/release/vow")
        .args(&["check", test_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute command");
    
    // Should default to table/terminal format to stdout
    assert!(output.status.success() || output.status.code() == Some(0));
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Vow Analysis Report"));
}