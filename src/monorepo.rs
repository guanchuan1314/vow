use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::{AnalysisResult, Config, load_config};

/// Different types of monorepo structures we can detect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonorepoType {
    Cargo,        // Rust cargo workspaces
    Npm,          // npm/yarn/pnpm workspaces
    GoModules,    // Go modules
    Bazel,        // Bazel workspaces
}

/// Information about a detected workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub name: String,
    pub path: PathBuf,
    pub workspace_type: MonorepoType,
    pub config_path: Option<PathBuf>,  // Path to per-workspace config if exists
}

/// Results grouped by workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonorepoResults {
    pub workspaces: HashMap<String, Vec<AnalysisResult>>,
    pub summary: MonorepoSummary,
}

/// Summary statistics across all workspaces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonorepoSummary {
    pub total_workspaces: usize,
    pub total_files: usize,
    pub avg_score_across_workspaces: u8,
    pub total_issues: usize,
    pub issues_by_workspace: HashMap<String, usize>,
    pub issues_by_severity: HashMap<String, usize>,
    pub workspace_summaries: HashMap<String, WorkspaceSummary>,
}

/// Summary for a single workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    pub files: usize,
    pub avg_score: u8,
    pub total_issues: usize,
    pub issues_by_severity: HashMap<String, usize>,
}

impl MonorepoType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MonorepoType::Cargo => "cargo",
            MonorepoType::Npm => "npm",
            MonorepoType::GoModules => "go",
            MonorepoType::Bazel => "bazel",
        }
    }
}

/// Detect if the given path is a monorepo and return workspace information
pub fn detect_monorepo(path: &Path) -> Option<Vec<Workspace>> {
    let mut workspaces = Vec::new();
    
    // Try to detect Cargo workspaces
    if let Some(mut cargo_workspaces) = detect_cargo_workspaces(path) {
        workspaces.append(&mut cargo_workspaces);
    }
    
    // Try to detect npm/yarn/pnpm workspaces
    if let Some(mut npm_workspaces) = detect_npm_workspaces(path) {
        workspaces.append(&mut npm_workspaces);
    }
    
    // Try to detect Go modules
    if let Some(mut go_workspaces) = detect_go_workspaces(path) {
        workspaces.append(&mut go_workspaces);
    }
    
    // Try to detect Bazel workspaces
    if let Some(mut bazel_workspaces) = detect_bazel_workspaces(path) {
        workspaces.append(&mut bazel_workspaces);
    }
    
    if workspaces.is_empty() {
        None
    } else {
        Some(workspaces)
    }
}

/// Detect Cargo workspaces by looking for Cargo.toml with [workspace] section
fn detect_cargo_workspaces(root: &Path) -> Option<Vec<Workspace>> {
    let cargo_toml = root.join("Cargo.toml");
    if !cargo_toml.exists() {
        return None;
    }
    
    let content = fs::read_to_string(&cargo_toml).ok()?;
    
    // Parse as TOML to check for workspace
    let toml: toml::Value = content.parse().ok()?;
    
    if let Some(workspace) = toml.get("workspace") {
        let mut workspaces = Vec::new();
        
        // Get workspace members
        if let Some(members) = workspace.get("members").and_then(|m| m.as_array()) {
            for member in members {
                if let Some(member_path) = member.as_str() {
                    let workspace_path = root.join(member_path);
                    if workspace_path.exists() {
                        let workspace_name = workspace_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(member_path)
                            .to_string();
                        
                        let config_path = check_workspace_config(&workspace_path);
                        
                        workspaces.push(Workspace {
                            name: workspace_name,
                            path: workspace_path,
                            workspace_type: MonorepoType::Cargo,
                            config_path,
                        });
                    }
                }
            }
        }
        
        // If no members found, treat root as single workspace
        if workspaces.is_empty() {
            let config_path = check_workspace_config(root);
            workspaces.push(Workspace {
                name: "root".to_string(),
                path: root.to_path_buf(),
                workspace_type: MonorepoType::Cargo,
                config_path,
            });
        }
        
        Some(workspaces)
    } else {
        // Single crate, treat as workspace
        let config_path = check_workspace_config(root);
        Some(vec![Workspace {
            name: "root".to_string(),
            path: root.to_path_buf(),
            workspace_type: MonorepoType::Cargo,
            config_path,
        }])
    }
}

/// Detect npm/yarn/pnpm workspaces
fn detect_npm_workspaces(root: &Path) -> Option<Vec<Workspace>> {
    let package_json = root.join("package.json");
    if !package_json.exists() {
        return None;
    }
    
    let content = fs::read_to_string(&package_json).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    
    let mut workspaces = Vec::new();
    
    // Check for npm/yarn workspaces
    if let Some(workspaces_def) = json.get("workspaces") {
        let patterns = match workspaces_def {
            serde_json::Value::Array(arr) => {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
            }
            serde_json::Value::Object(obj) => {
                if let Some(packages) = obj.get("packages").and_then(|p| p.as_array()) {
                    packages.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                } else {
                    return None;
                }
            }
            serde_json::Value::String(s) => vec![s.as_str()],
            _ => return None,
        };
        
        // Expand glob patterns to find actual workspace directories
        for pattern in patterns {
            if let Ok(entries) = glob::glob(&root.join(pattern).to_string_lossy()) {
                for entry in entries.flatten() {
                    if entry.is_dir() && entry.join("package.json").exists() {
                        let workspace_name = entry.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unnamed")
                            .to_string();
                        
                        let config_path = check_workspace_config(&entry);
                        
                        workspaces.push(Workspace {
                            name: workspace_name,
                            path: entry,
                            workspace_type: MonorepoType::Npm,
                            config_path,
                        });
                    }
                }
            }
        }
    }
    
    // If no workspaces found but package.json exists, treat as single workspace
    if workspaces.is_empty() {
        let config_path = check_workspace_config(root);
        workspaces.push(Workspace {
            name: "root".to_string(),
            path: root.to_path_buf(),
            workspace_type: MonorepoType::Npm,
            config_path,
        });
    }
    
    Some(workspaces)
}

/// Detect Go modules by looking for go.work or multiple go.mod files
fn detect_go_workspaces(root: &Path) -> Option<Vec<Workspace>> {
    let go_work = root.join("go.work");
    let mut workspaces = Vec::new();
    
    if go_work.exists() {
        // Parse go.work file for modules
        if let Ok(content) = fs::read_to_string(&go_work) {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("use ") {
                    let path_part = line.strip_prefix("use ").unwrap().trim();
                    let module_path = root.join(path_part);
                    if module_path.exists() && module_path.join("go.mod").exists() {
                        let workspace_name = module_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(path_part)
                            .to_string();
                        
                        let config_path = check_workspace_config(&module_path);
                        
                        workspaces.push(Workspace {
                            name: workspace_name,
                            path: module_path,
                            workspace_type: MonorepoType::GoModules,
                            config_path,
                        });
                    }
                }
            }
        }
    } else {
        // Look for multiple go.mod files in subdirectories
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                if entry.file_type().ok().map_or(false, |ft| ft.is_dir()) {
                    let go_mod = entry.path().join("go.mod");
                    if go_mod.exists() {
                        let workspace_name = entry.file_name().to_string_lossy().to_string();
                        let config_path = check_workspace_config(&entry.path());
                        
                        workspaces.push(Workspace {
                            name: workspace_name,
                            path: entry.path(),
                            workspace_type: MonorepoType::GoModules,
                            config_path,
                        });
                    }
                }
            }
        }
        
        // If no modules found in subdirs, check if root has go.mod
        if workspaces.is_empty() && root.join("go.mod").exists() {
            let config_path = check_workspace_config(root);
            workspaces.push(Workspace {
                name: "root".to_string(),
                path: root.to_path_buf(),
                workspace_type: MonorepoType::GoModules,
                config_path,
            });
        }
    }
    
    if workspaces.is_empty() {
        None
    } else {
        Some(workspaces)
    }
}

/// Detect Bazel workspaces by looking for WORKSPACE or WORKSPACE.bazel files
fn detect_bazel_workspaces(root: &Path) -> Option<Vec<Workspace>> {
    let workspace_file = root.join("WORKSPACE");
    let workspace_bazel = root.join("WORKSPACE.bazel");
    
    if workspace_file.exists() || workspace_bazel.exists() {
        // For Bazel, we typically treat the entire repo as one workspace
        // but we could potentially look for BUILD files in subdirectories
        let config_path = check_workspace_config(root);
        
        Some(vec![Workspace {
            name: "root".to_string(),
            path: root.to_path_buf(),
            workspace_type: MonorepoType::Bazel,
            config_path,
        }])
    } else {
        None
    }
}

/// Check if a workspace has its own .vow/config.yaml
fn check_workspace_config(workspace_path: &Path) -> Option<PathBuf> {
    let config_path = workspace_path.join(".vow").join("config.yaml");
    if config_path.exists() {
        Some(config_path)
    } else {
        None
    }
}

/// Load configuration for a workspace, with fallback to parent configs
pub fn load_workspace_config(workspace: &Workspace, root_config: &Config) -> Result<Config, Box<dyn std::error::Error>> {
    if let Some(_config_path) = &workspace.config_path {
        // Load workspace-specific config and merge with root config
        let workspace_config = load_config(&workspace.path)?;
        Ok(merge_configs(root_config, &workspace_config))
    } else {
        // Use root config
        Ok(root_config.clone())
    }
}

/// Merge two configs, with workspace config taking precedence
fn merge_configs(root: &Config, workspace: &Config) -> Config {
    Config {
        analyzers: workspace.analyzers.clone().or(root.analyzers.clone()),
        output: workspace.output.clone().or(root.output.clone()),
        exclude: workspace.exclude.clone().or(root.exclude.clone()),
        allowlists: workspace.allowlists.clone().or(root.allowlists.clone()),
        quiet: workspace.quiet.or(root.quiet),
        fail_threshold: workspace.fail_threshold.or(root.fail_threshold),
        min_severity: workspace.min_severity.clone().or(root.min_severity.clone()),
        threshold: workspace.threshold.or(root.threshold),
        enabled_analyzers: workspace.enabled_analyzers.clone().or(root.enabled_analyzers.clone()),
        custom_rule_dirs: workspace.custom_rule_dirs.clone().or(root.custom_rule_dirs.clone()),
        max_file_size_mb: workspace.max_file_size_mb.or(root.max_file_size_mb),
        max_directory_depth: workspace.max_directory_depth.or(root.max_directory_depth),
        max_issues_per_file: workspace.max_issues_per_file.or(root.max_issues_per_file),
        parallel_processing: workspace.parallel_processing.or(root.parallel_processing),
    }
}

/// Create aggregated summary from workspace results
pub fn create_monorepo_summary(
    workspace_results: &HashMap<String, Vec<AnalysisResult>>,
) -> MonorepoSummary {
    let mut total_files = 0;
    let mut total_issues = 0;
    let mut issues_by_severity = HashMap::new();
    let mut issues_by_workspace = HashMap::new();
    let mut workspace_summaries = HashMap::new();
    let mut total_score_sum = 0u64;
    let mut total_files_with_scores = 0;
    
    for (workspace_name, results) in workspace_results {
        let workspace_files = results.len();
        let workspace_issues: usize = results.iter().map(|r| r.issues.len()).sum();
        let workspace_score_sum: u64 = results.iter().map(|r| r.trust_score as u64).sum();
        let workspace_avg_score = if workspace_files > 0 {
            (workspace_score_sum / workspace_files as u64) as u8
        } else {
            100
        };
        
        let mut workspace_severity_counts = HashMap::new();
        
        for result in results {
            total_files_with_scores += 1;
            total_score_sum += result.trust_score as u64;
            
            for issue in &result.issues {
                let severity_str = format!("{:?}", issue.severity).to_lowercase();
                *issues_by_severity.entry(severity_str.clone()).or_insert(0) += 1;
                *workspace_severity_counts.entry(severity_str).or_insert(0) += 1;
            }
        }
        
        total_files += workspace_files;
        total_issues += workspace_issues;
        issues_by_workspace.insert(workspace_name.clone(), workspace_issues);
        
        workspace_summaries.insert(workspace_name.clone(), WorkspaceSummary {
            files: workspace_files,
            avg_score: workspace_avg_score,
            total_issues: workspace_issues,
            issues_by_severity: workspace_severity_counts,
        });
    }
    
    let avg_score_across_workspaces = if total_files_with_scores > 0 {
        (total_score_sum / total_files_with_scores as u64) as u8
    } else {
        100
    };
    
    MonorepoSummary {
        total_workspaces: workspace_results.len(),
        total_files,
        avg_score_across_workspaces,
        total_issues,
        issues_by_workspace,
        issues_by_severity,
        workspace_summaries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    #[test]
    fn test_detect_cargo_workspace() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        
        // Create a Cargo.toml with workspace
        let cargo_toml = r#"
[workspace]
members = ["crate-a", "crate-b"]
"#;
        fs::write(root.join("Cargo.toml"), cargo_toml).unwrap();
        
        // Create workspace members
        fs::create_dir_all(root.join("crate-a")).unwrap();
        fs::write(root.join("crate-a/Cargo.toml"), "[package]\nname = \"crate-a\"\nversion = \"0.1.0\"").unwrap();
        
        fs::create_dir_all(root.join("crate-b")).unwrap();
        fs::write(root.join("crate-b/Cargo.toml"), "[package]\nname = \"crate-b\"\nversion = \"0.1.0\"").unwrap();
        
        let workspaces = detect_monorepo(root).unwrap();
        assert_eq!(workspaces.len(), 2);
        assert!(workspaces.iter().any(|w| w.name == "crate-a" && matches!(w.workspace_type, MonorepoType::Cargo)));
        assert!(workspaces.iter().any(|w| w.name == "crate-b" && matches!(w.workspace_type, MonorepoType::Cargo)));
    }
    
    #[test]
    fn test_detect_npm_workspace() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        
        // Create package.json with workspaces
        let package_json = r#"
{
  "name": "monorepo",
  "workspaces": ["packages/*"]
}
"#;
        fs::write(root.join("package.json"), package_json).unwrap();
        
        // Create workspace members
        fs::create_dir_all(root.join("packages/pkg-a")).unwrap();
        fs::write(root.join("packages/pkg-a/package.json"), r#"{"name": "pkg-a"}"#).unwrap();
        
        fs::create_dir_all(root.join("packages/pkg-b")).unwrap();
        fs::write(root.join("packages/pkg-b/package.json"), r#"{"name": "pkg-b"}"#).unwrap();
        
        let workspaces = detect_monorepo(root).unwrap();
        assert_eq!(workspaces.len(), 2);
        assert!(workspaces.iter().any(|w| w.name == "pkg-a" && matches!(w.workspace_type, MonorepoType::Npm)));
        assert!(workspaces.iter().any(|w| w.name == "pkg-b" && matches!(w.workspace_type, MonorepoType::Npm)));
    }
}