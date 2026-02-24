use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::fmt::Write;

use crate::{AnalysisResult, Issue, Severity};

/// A fingerprint for identifying a specific issue
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IssueFingerprint {
    pub file_path: String,
    pub rule: String,
    pub line_content_hash: String,
}

/// Baseline data structure that stores known issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: String,
    pub created_at: String,
    pub fingerprints: Vec<IssueFingerprint>,
}

impl Baseline {
    /// Create a new empty baseline
    pub fn new() -> Self {
        Baseline {
            version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            fingerprints: Vec::new(),
        }
    }

    /// Add an issue fingerprint to the baseline
    pub fn add_fingerprint(&mut self, fingerprint: IssueFingerprint) {
        if !self.fingerprints.contains(&fingerprint) {
            self.fingerprints.push(fingerprint);
        }
    }

    /// Sort fingerprints for deterministic output
    pub fn sort(&mut self) {
        self.fingerprints.sort_by(|a, b| {
            a.file_path.cmp(&b.file_path)
                .then_with(|| a.rule.cmp(&b.rule))
                .then_with(|| a.line_content_hash.cmp(&b.line_content_hash))
        });
    }
}

/// Create a fingerprint for an issue
pub fn create_issue_fingerprint(
    file_path: &Path, 
    issue: &Issue,
    file_content: &str
) -> Result<IssueFingerprint, Box<dyn std::error::Error>> {
    let rule = issue.rule.as_ref().unwrap_or(&"unknown".to_string()).clone();
    
    // Calculate hash of the line content (or full content if no line number)
    let line_content = if let Some(line_num) = issue.line {
        let lines: Vec<&str> = file_content.lines().collect();
        if line_num > 0 && line_num <= lines.len() {
            lines[line_num - 1] // line numbers are 1-indexed
        } else {
            "" // fallback for invalid line numbers
        }
    } else {
        // If no line number, hash the first 100 chars of the issue message
        &issue.message.chars().take(100).collect::<String>()
    };
    
    let mut hasher = Sha256::new();
    hasher.update(line_content.trim().as_bytes());
    let result = hasher.finalize();
    
    let mut hash_string = String::with_capacity(64);
    for byte in result.iter() {
        write!(hash_string, "{:02x}", byte)?;
    }

    Ok(IssueFingerprint {
        file_path: file_path.to_string_lossy().to_string(),
        rule,
        line_content_hash: hash_string,
    })
}

/// Generate baseline from analysis results
pub fn generate_baseline_from_results(
    results: &[AnalysisResult]
) -> Result<Baseline, Box<dyn std::error::Error>> {
    let mut baseline = Baseline::new();
    
    for result in results {
        if result.issues.is_empty() {
            continue;
        }
        
        // Read file content for hashing
        let file_content = fs::read_to_string(&result.path)
            .unwrap_or_else(|_| String::new());
        
        for issue in &result.issues {
            let fingerprint = create_issue_fingerprint(&result.path, issue, &file_content)?;
            baseline.add_fingerprint(fingerprint);
        }
    }
    
    baseline.sort();
    Ok(baseline)
}

/// Save baseline to .vow/baseline.json
pub fn save_baseline(
    project_root: &Path, 
    baseline: &Baseline
) -> Result<(), Box<dyn std::error::Error>> {
    let vow_dir = project_root.join(".vow");
    if !vow_dir.exists() {
        fs::create_dir_all(&vow_dir)?;
    }
    
    let baseline_path = vow_dir.join("baseline.json");
    let baseline_content = serde_json::to_string_pretty(baseline)?;
    fs::write(&baseline_path, baseline_content)?;
    
    Ok(())
}

/// Load baseline from .vow/baseline.json
pub fn load_baseline(project_root: &Path) -> Result<Option<Baseline>, Box<dyn std::error::Error>> {
    let baseline_path = project_root.join(".vow").join("baseline.json");
    
    if !baseline_path.exists() {
        return Ok(None);
    }
    
    let baseline_content = fs::read_to_string(&baseline_path)?;
    let baseline: Baseline = serde_json::from_str(&baseline_content)?;
    
    Ok(Some(baseline))
}

/// Remove baseline file
pub fn clear_baseline(project_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let baseline_path = project_root.join(".vow").join("baseline.json");
    
    if baseline_path.exists() {
        fs::remove_file(&baseline_path)?;
    }
    
    Ok(())
}

/// Filter analysis results against baseline
pub fn filter_baseline_issues(
    results: Vec<AnalysisResult>,
    baseline: &Baseline
) -> Result<Vec<AnalysisResult>, Box<dyn std::error::Error>> {
    let mut filtered_results = Vec::new();
    
    // Create a lookup set of baseline fingerprints for O(1) checking
    let baseline_set: HashMap<IssueFingerprint, ()> = baseline.fingerprints
        .iter()
        .map(|fp| (fp.clone(), ()))
        .collect();
    
    for mut result in results {
        if result.issues.is_empty() {
            filtered_results.push(result);
            continue;
        }
        
        // Read file content for fingerprinting
        let file_content = fs::read_to_string(&result.path)
            .unwrap_or_else(|_| String::new());
        
        let mut filtered_issues = Vec::new();
        
        for issue in result.issues {
            let fingerprint = create_issue_fingerprint(&result.path, &issue, &file_content)?;
            
            // Only keep issues that are NOT in the baseline
            if !baseline_set.contains_key(&fingerprint) {
                filtered_issues.push(issue);
            }
        }
        
        // Update the result with filtered issues
        result.issues = filtered_issues;
        
        // Recalculate trust score
        result.trust_score = crate::calculate_trust_score(&result.issues);
        
        filtered_results.push(result);
    }
    
    Ok(filtered_results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileType, Severity};
    use tempfile::TempDir;
    
    #[test]
    fn test_baseline_creation() {
        let baseline = Baseline::new();
        assert_eq!(baseline.version, env!("CARGO_PKG_VERSION"));
        assert!(baseline.fingerprints.is_empty());
    }
    
    #[test]
    fn test_issue_fingerprint_creation() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.py");
        let content = "print('hello')\neval('bad code')\nprint('world')";
        fs::write(&test_file, content).unwrap();
        
        let issue = Issue {
            severity: Severity::High,
            message: "Dangerous eval usage".to_string(),
            line: Some(2),
            rule: Some("eval_usage".to_string()),
        };
        
        let fingerprint = create_issue_fingerprint(&test_file, &issue, content).unwrap();
        
        assert_eq!(fingerprint.file_path, test_file.to_string_lossy());
        assert_eq!(fingerprint.rule, "eval_usage");
        assert!(!fingerprint.line_content_hash.is_empty());
    }
    
    #[test]
    fn test_baseline_filtering() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.py");
        let content = "eval('bad code')";
        fs::write(&test_file, content).unwrap();
        
        // Create baseline issue
        let baseline_issue = Issue {
            severity: Severity::High,
            message: "Dangerous eval usage".to_string(),
            line: Some(1),
            rule: Some("eval_usage".to_string()),
        };
        
        let fingerprint = create_issue_fingerprint(&test_file, &baseline_issue, content).unwrap();
        
        let mut baseline = Baseline::new();
        baseline.add_fingerprint(fingerprint);
        
        // Create analysis result with same issue
        let result = AnalysisResult {
            path: test_file.clone(),
            file_type: FileType::Python,
            issues: vec![baseline_issue.clone()],
            trust_score: 75,
        };
        
        let filtered = filter_baseline_issues(vec![result], &baseline).unwrap();
        
        // Issue should be filtered out
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].issues.is_empty());
        assert_eq!(filtered[0].trust_score, 100); // Trust score should be recalculated
    }
    
    #[test]
    fn test_baseline_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let mut baseline = Baseline::new();
        
        baseline.add_fingerprint(IssueFingerprint {
            file_path: "test.py".to_string(),
            rule: "test_rule".to_string(),
            line_content_hash: "abc123".to_string(),
        });
        
        // Save baseline
        save_baseline(temp_dir.path(), &baseline).unwrap();
        
        // Check file exists
        let baseline_path = temp_dir.path().join(".vow").join("baseline.json");
        assert!(baseline_path.exists());
        
        // Load baseline
        let loaded = load_baseline(temp_dir.path()).unwrap().unwrap();
        assert_eq!(loaded.fingerprints.len(), 1);
        assert_eq!(loaded.fingerprints[0].file_path, "test.py");
        assert_eq!(loaded.fingerprints[0].rule, "test_rule");
    }
    
    #[test]
    fn test_baseline_clear() {
        let temp_dir = TempDir::new().unwrap();
        let baseline = Baseline::new();
        
        // Save baseline
        save_baseline(temp_dir.path(), &baseline).unwrap();
        let baseline_path = temp_dir.path().join(".vow").join("baseline.json");
        assert!(baseline_path.exists());
        
        // Clear baseline
        clear_baseline(temp_dir.path()).unwrap();
        assert!(!baseline_path.exists());
    }
    
    #[test]
    fn test_baseline_sorting() {
        let mut baseline = Baseline::new();
        
        // Add fingerprints in random order
        baseline.add_fingerprint(IssueFingerprint {
            file_path: "z.py".to_string(),
            rule: "rule1".to_string(),
            line_content_hash: "hash1".to_string(),
        });
        
        baseline.add_fingerprint(IssueFingerprint {
            file_path: "a.py".to_string(),
            rule: "rule2".to_string(),
            line_content_hash: "hash2".to_string(),
        });
        
        baseline.sort();
        
        // Should be sorted by file_path first
        assert_eq!(baseline.fingerprints[0].file_path, "a.py");
        assert_eq!(baseline.fingerprints[1].file_path, "z.py");
    }
}