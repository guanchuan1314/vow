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
        /// Output format (table, json, sarif)
        #[arg(short = 'o', long, value_name = "FORMAT")]
        output: Option<String>,
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
}

#[derive(Subcommand)]
enum HookAction {
    /// Install git pre-commit hook
    Install,
    /// Uninstall git pre-commit hook
    Uninstall,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            vow::init_project(path)?;
        }
        Commands::Check { path, output, analyzers, exclude, allowlists, quiet, fail_threshold, no_config, rules, threshold, ci, verbose, hook_mode, watch, max_file_size, max_depth, max_issues } => {
            let path_str = if hook_mode {
                "-".to_string() // In hook mode, we read from stdin
            } else {
                path.unwrap_or(".".to_string()) // Default to current directory if no path provided
            };
            
            if watch {
                // Watch mode - never exits unless interrupted
                vow::watch_files(path_str, output, analyzers, exclude, allowlists, quiet, fail_threshold, no_config, rules, threshold, ci, verbose, max_file_size, max_depth, max_issues)?;
            } else {
                let exit_code = vow::check_input(path_str, output, analyzers, exclude, allowlists, quiet, fail_threshold, no_config, rules, threshold, ci, verbose, hook_mode, max_file_size, max_depth, max_issues)?;
                std::process::exit(exit_code);
            }
        }
        Commands::Scan { target, ports, format, timeout, concurrency, issues_only } => {
            let exit_code = vow::scan_ports(target, ports, format, timeout, concurrency, issues_only)?;
            std::process::exit(exit_code);
        }
        Commands::Hooks { action } => {
            match action {
                HookAction::Install => {
                    vow::hooks_install()?;
                }
                HookAction::Uninstall => {
                    vow::hooks_uninstall()?;
                }
            }
        }
    }

    Ok(())
}