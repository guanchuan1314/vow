use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Vow - A local-first AI output verification engine
#[derive(Parser)]
#[command(name = "vow")]
#[command(about = "A local-first AI output verification engine")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Vow project
    Init {
        /// Directory to initialize (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Check a file, directory, or stdin for verification
    Check {
        /// Path to analyze (file or directory), or "-" for stdin
        path: Option<String>,
        /// Output format(s) - single format: table, json, sarif; multiple formats: text,json,sarif
        #[arg(short = 'f', long, value_name = "FORMAT", value_delimiter = ',')]
        format: Option<Vec<String>>,
        /// Output directory for multi-format reports (required when multiple formats specified)
        #[arg(long, value_name = "DIR")]
        output_dir: Option<std::path::PathBuf>,
        /// Analyzers to enable (code, text, security)
        #[arg(short = 'a', long, value_delimiter = ',', value_name = "ANALYZER")]
        analyzers: Option<Vec<String>>,
        /// Files/dirs to exclude  
        #[arg(short, long, value_delimiter = ',', value_name = "PATTERN")]
        exclude: Option<Vec<String>>,
        /// Custom allowlist paths
        #[arg(long, value_delimiter = ',', value_name = "PATH")]
        allowlists: Option<Vec<PathBuf>>,
        /// Quiet mode (errors only)
        #[arg(short, long)]
        quiet: Option<bool>,
        /// Fail threshold (exit 1 if issues >= threshold)
        #[arg(long, value_name = "COUNT")]
        fail_threshold: Option<u32>,
        /// Skip config file loading
        #[arg(long)]
        no_config: bool,
        /// Rule file or directory
        #[arg(short, long)]
        rules: Option<PathBuf>,
        /// Trust score threshold (exit code 1 if below)
        #[arg(long)]
        threshold: Option<u8>,
        /// CI mode (JSON output, non-zero exit on failure)
        #[arg(long)]
        ci: bool,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
        /// Hook mode: accept file list via stdin
        #[arg(long)]
        hook_mode: bool,
        /// Watch mode: continuously monitor for file changes
        #[arg(long)]
        watch: bool,
        /// Maximum file size to process in MB
        #[arg(long, default_value = "10")]
        max_file_size: u64,
        /// Maximum directory depth to scan
        #[arg(long, default_value = "20")]
        max_depth: usize,
        /// Maximum issues per file before moving on
        #[arg(long, default_value = "100")]
        max_issues: usize,
        /// Skip cache and analyze all files
        #[arg(long)]
        no_cache: bool,
        /// Clear cache and exit
        #[arg(long)]
        clear_cache: bool,
        /// Summary mode: show compact one-line-per-file report
        #[arg(long)]
        summary: bool,
        /// Use baseline to ignore known issues
        #[arg(long)]
        baseline: bool,
        /// Diff mode: only analyze files changed in git (optional argument: commit range, staged, unstaged)
        #[arg(long, value_name = "RANGE")]
        diff: Option<Option<String>>,
        /// Auto-apply fix suggestions where possible
        #[arg(long)]
        fix: bool,
        /// Show fix suggestions inline without applying them
        #[arg(long)]
        suggest: bool,
        /// Minimum severity threshold (low, medium, high, critical)
        #[arg(long, value_name = "LEVEL")]
        min_severity: Option<String>,
    },
    /// Scan network ports and evaluate security
    Scan {
        /// Target to scan (IP address, hostname, or CIDR range)
        target: String,
        /// Port range to scan (e.g., 1-1000, 22,80,443)
        #[arg(short, long, default_value = "1-1000")]
        ports: String,
        /// Output format
        #[arg(short, long, default_value = "terminal")]
        format: String,
        /// Timeout per port in milliseconds
        #[arg(long, default_value = "1000")]
        timeout: u64,
        /// Number of concurrent scans
        #[arg(short, long, default_value = "100")]
        concurrency: usize,
        /// Only report security issues (skip secure ports)
        #[arg(long)]
        issues_only: bool,
    },
    /// Manage git hooks integration
    Hooks {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Manage baseline of known issues
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Show aggregate statistics from scan history
    Stats {
        /// Output in JSON format for machine-readable output
        #[arg(long)]
        json: bool,
        /// Number of recent scans to include in trend analysis
        #[arg(long, default_value = "10")]
        last_n: usize,
    },
}

#[derive(Subcommand)]
enum HookAction {
    /// Install git hooks
    Install {
        /// Install pre-push hook instead of pre-commit hook
        #[arg(long)]
        pre_push: bool,
    },
    /// Uninstall git hooks
    Uninstall {
        /// Uninstall pre-push hook instead of pre-commit hook
        #[arg(long)]
        pre_push: bool,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Create baseline from current analysis results
    Create {
        /// Path to analyze (file or directory)
        #[arg(default_value = ".")]
        path: String,
        /// Analyzers to enable (code, text, security)
        #[arg(short = 'a', long, value_delimiter = ',', value_name = "ANALYZER")]
        analyzers: Option<Vec<String>>,
        /// Files/dirs to exclude
        #[arg(short, long, value_delimiter = ',', value_name = "PATTERN")]
        exclude: Option<Vec<String>>,
        /// Custom allowlist paths
        #[arg(long, value_delimiter = ',', value_name = "PATH")]
        allowlists: Option<Vec<PathBuf>>,
        /// Skip config file loading
        #[arg(long)]
        no_config: bool,
        /// Rule file or directory
        #[arg(short, long)]
        rules: Option<PathBuf>,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
        /// Maximum file size to process in MB
        #[arg(long, default_value = "10")]
        max_file_size: u64,
        /// Maximum directory depth to scan
        #[arg(long, default_value = "20")]
        max_depth: usize,
        /// Maximum issues per file before moving on
        #[arg(long, default_value = "100")]
        max_issues: usize,
    },
    /// Remove baseline file
    Clear {
        /// Path to project (default: current directory)
        #[arg(default_value = ".")]
        path: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            vow::init_project(path)?;
        }
        Commands::Check { path, format, output_dir, analyzers, exclude, allowlists, quiet, fail_threshold, no_config, rules, threshold, ci, verbose, hook_mode, watch, max_file_size, max_depth, max_issues, no_cache, clear_cache, summary, baseline, diff, fix, suggest, min_severity } => {
            let path_str = if hook_mode {
                "-".to_string() // In hook mode, we read from stdin
            } else {
                path.unwrap_or(".".to_string()) // Default to current directory if no path provided
            };
            
            if clear_cache {
                // Clear cache and exit
                vow::clear_cache(&path_str)?;
                println!("Cache cleared.");
                std::process::exit(0);
            }
            
            if watch {
                // Watch mode - never exits unless interrupted
                vow::watch_files(path_str, format, output_dir, analyzers, exclude, allowlists, quiet, fail_threshold, no_config, rules, threshold, ci, verbose, max_file_size, max_depth, max_issues, no_cache, summary, baseline, diff, fix, suggest, min_severity)?;
            } else {
                let exit_code = vow::check_input(path_str, format, output_dir, analyzers, exclude, allowlists, quiet, fail_threshold, no_config, rules, threshold, ci, verbose, hook_mode, max_file_size, max_depth, max_issues, no_cache, summary, baseline, diff, fix, suggest, min_severity)?;
                std::process::exit(exit_code);
            }
        }
        Commands::Scan { target, ports, format, timeout, concurrency, issues_only } => {
            let exit_code = vow::scan_ports(target, ports, format, timeout, concurrency, issues_only)?;
            std::process::exit(exit_code);
        }
        Commands::Hooks { action } => {
            match action {
                HookAction::Install { pre_push } => {
                    if pre_push {
                        vow::hooks_install_pre_push()?;
                    } else {
                        vow::hooks_install()?;
                    }
                }
                HookAction::Uninstall { pre_push } => {
                    if pre_push {
                        vow::hooks_uninstall_pre_push()?;
                    } else {
                        vow::hooks_uninstall()?;
                    }
                }
            }
        }
        Commands::Baseline { action } => {
            match action {
                BaselineAction::Create { path, analyzers, exclude, allowlists, no_config, rules, verbose, max_file_size, max_depth, max_issues } => {
                    vow::baseline_create(path, analyzers, exclude, allowlists, no_config, rules, verbose, max_file_size, max_depth, max_issues)?;
                }
                BaselineAction::Clear { path } => {
                    vow::baseline_clear(path)?;
                }
            }
        }
        Commands::Stats { json, last_n } => {
            vow::stats::display_stats_from_history(json, last_n)?;
        }
    }

    Ok(())
}