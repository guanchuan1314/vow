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
    /// Check a file, directory, or stdin for verification
    Check {
        /// Path to analyze (file or directory)
        path: PathBuf,
        /// Output format
        #[arg(short, long, default_value = "terminal")]
        format: String,
        /// Rule file or directory
        #[arg(short, long)]
        rules: Option<PathBuf>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check { path, format, rules } => {
            vow::check_path(path, format, rules)?;
        }
    }

    Ok(())
}