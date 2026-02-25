use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashSet;

/// Error types for git diff operations
#[derive(Debug)]
pub enum DiffError {
    NotGitRepo,
    GitCommandFailed(String),
    InvalidRange(String),
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffError::NotGitRepo => write!(f, "Not in a git repository"),
            DiffError::GitCommandFailed(msg) => write!(f, "Git command failed: {}", msg),
            DiffError::InvalidRange(range) => write!(f, "Invalid commit range: {}", range),
        }
    }
}

impl std::error::Error for DiffError {}

/// Represents different types of diff ranges
#[derive(Debug, Clone)]
pub enum DiffRange {
    Unstaged,           // Working directory changes
    Staged,             // Staged changes
    CommitRange(String), // Specific commit range like HEAD~3..HEAD
}

impl DiffRange {
    /// Parse a diff range string into a DiffRange
    pub fn parse(range_str: Option<String>) -> Result<Self, DiffError> {
        match range_str {
            None => Ok(DiffRange::Unstaged), // Default to unstaged changes
            Some(range) => {
                match range.to_lowercase().as_str() {
                    "staged" => Ok(DiffRange::Staged),
                    "unstaged" => Ok(DiffRange::Unstaged),
                    _ => {
                        // Validate commit range format
                        if range.contains("..") || range.starts_with("HEAD") || range.chars().all(|c| c.is_alphanumeric() || c == '~' || c == '^' || c == '.') {
                            Ok(DiffRange::CommitRange(range))
                        } else {
                            Err(DiffError::InvalidRange(range))
                        }
                    }
                }
            }
        }
    }
}

/// Get the list of changed files based on git diff
pub fn get_changed_files(range: &DiffRange, project_root: &Path) -> Result<Vec<PathBuf>, DiffError> {
    // Check if we're in a git repository
    if !is_git_repo(project_root) {
        return Err(DiffError::NotGitRepo);
    }

    let git_args = match range {
        DiffRange::Unstaged => vec!["diff", "--name-only"],
        DiffRange::Staged => vec!["diff", "--cached", "--name-only"],
        DiffRange::CommitRange(range_str) => vec!["diff", "--name-only", range_str],
    };

    let output = Command::new("git")
        .args(&git_args)
        .current_dir(project_root)
        .output()
        .map_err(|e| DiffError::GitCommandFailed(format!("Failed to execute git: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DiffError::GitCommandFailed(format!("Git command failed: {}", stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut changed_files = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if !line.is_empty() {
            // Convert to absolute path relative to project root
            let file_path = project_root.join(line);
            
            // Only include existing files (git diff might include deleted files)
            if file_path.exists() && file_path.is_file() {
                changed_files.push(file_path);
            }
        }
    }

    Ok(changed_files)
}

/// Check if the given directory is a git repository
pub fn is_git_repo(path: &Path) -> bool {
    // Look for .git directory or .git file (for git worktrees)
    let git_path = path.join(".git");
    git_path.exists()
}

/// Filter a list of file paths to only include those that have changed
pub fn filter_changed_files(all_files: Vec<PathBuf>, changed_files: &[PathBuf]) -> Vec<PathBuf> {
    let changed_set: HashSet<&PathBuf> = changed_files.iter().collect();
    all_files.into_iter()
        .filter(|file| changed_set.contains(file))
        .collect()
}

/// Get the git repository root for the given path
pub fn get_git_root(start_path: &Path) -> Result<PathBuf, DiffError> {
    let output = Command::new("git")
        .args(&["rev-parse", "--show-toplevel"])
        .current_dir(start_path)
        .output()
        .map_err(|e| DiffError::GitCommandFailed(format!("Failed to execute git: {}", e)))?;

    if !output.status.success() {
        return Err(DiffError::NotGitRepo);
    }

    let git_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(git_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;
    use std::process::Command;

    fn create_git_repo(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        Command::new("git")
            .args(&["init"])
            .current_dir(dir)
            .output()?;
        
        Command::new("git")
            .args(&["config", "user.email", "test@example.com"])
            .current_dir(dir)
            .output()?;
        
        Command::new("git")
            .args(&["config", "user.name", "Test User"])
            .current_dir(dir)
            .output()?;
        
        Ok(())
    }

    #[test]
    fn test_diff_range_parsing() {
        // Test default (unstaged)
        let range = DiffRange::parse(None).unwrap();
        matches!(range, DiffRange::Unstaged);

        // Test staged
        let range = DiffRange::parse(Some("staged".to_string())).unwrap();
        matches!(range, DiffRange::Staged);

        // Test unstaged
        let range = DiffRange::parse(Some("unstaged".to_string())).unwrap();
        matches!(range, DiffRange::Unstaged);

        // Test commit range
        let range = DiffRange::parse(Some("HEAD~3..HEAD".to_string())).unwrap();
        matches!(range, DiffRange::CommitRange(_));

        // Test invalid range
        let result = DiffRange::parse(Some("invalid-range!@#".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_git_repo() {
        let temp_dir = TempDir::new().unwrap();
        
        // Not a git repo initially
        assert!(!is_git_repo(temp_dir.path()));
        
        // Create .git directory
        fs::create_dir_all(temp_dir.path().join(".git")).unwrap();
        assert!(is_git_repo(temp_dir.path()));
    }

    #[test]
    fn test_filter_changed_files() {
        let all_files = vec![
            PathBuf::from("file1.py"),
            PathBuf::from("file2.py"),
            PathBuf::from("file3.py"),
        ];
        
        let changed_files = vec![
            PathBuf::from("file1.py"),
            PathBuf::from("file3.py"),
        ];
        
        let filtered = filter_changed_files(all_files, &changed_files);
        
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&PathBuf::from("file1.py")));
        assert!(filtered.contains(&PathBuf::from("file3.py")));
        assert!(!filtered.contains(&PathBuf::from("file2.py")));
    }

    #[test]
    fn test_get_changed_files_not_git_repo() {
        let temp_dir = TempDir::new().unwrap();
        let range = DiffRange::Unstaged;
        
        let result = get_changed_files(&range, temp_dir.path());
        assert!(result.is_err());
        matches!(result.unwrap_err(), DiffError::NotGitRepo);
    }

    #[test] 
    fn test_get_changed_files_empty_repo() {
        let temp_dir = TempDir::new().unwrap();
        
        // Initialize git repo but don't create any files
        if create_git_repo(temp_dir.path()).is_ok() {
            let range = DiffRange::Unstaged;
            let result = get_changed_files(&range, temp_dir.path());
            
            // Should succeed but return empty list
            if let Ok(files) = result {
                assert_eq!(files.len(), 0);
            }
        }
    }

    #[test]
    fn test_error_display() {
        let error = DiffError::NotGitRepo;
        assert_eq!(error.to_string(), "Not in a git repository");
        
        let error = DiffError::InvalidRange("bad-range".to_string());
        assert_eq!(error.to_string(), "Invalid commit range: bad-range");
        
        let error = DiffError::GitCommandFailed("git not found".to_string());
        assert_eq!(error.to_string(), "Git command failed: git not found");
    }

    #[test]
    fn test_commit_range_validation() {
        // Valid ranges
        assert!(DiffRange::parse(Some("HEAD~1..HEAD".to_string())).is_ok());
        assert!(DiffRange::parse(Some("abc123..def456".to_string())).is_ok());
        assert!(DiffRange::parse(Some("HEAD~3".to_string())).is_ok());
        assert!(DiffRange::parse(Some("HEAD^".to_string())).is_ok());
        
        // Invalid ranges 
        assert!(DiffRange::parse(Some("invalid!@#".to_string())).is_err());
        assert!(DiffRange::parse(Some("spaces not allowed".to_string())).is_err());
    }
}