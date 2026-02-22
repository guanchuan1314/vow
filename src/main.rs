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
        path: String,
        /// Output format
        #[arg(short, long, default_value = "terminal")]
        format: String,
        /// Rule file or directory
        #[arg(short, long)]
        rules: Option<PathBuf>,
        /// Trust score threshold (exit code 1 if below)
        #[arg(long)]
        threshold: Option<u8>,
        /// CI mode (JSON output, non-zero exit on failure)
        #[arg(long)]
        ci: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            vow::init_project(path)?;
        }
        Commands::Check { path, format, rules, threshold, ci } => {
            let exit_code = vow::check_input(path, format, rules, threshold, ci)?;
            std::process::exit(exit_code);
        }
    }

    Ok(())
}