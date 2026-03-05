use crate::{ProjectResults, Severity};
use owo_colors::OwoColorize;

/// Print results to terminal with colors and formatting
pub fn print_terminal_report(results: &ProjectResults) {
    println!("{}", "Vow Analysis Report".bold().cyan());
    println!("{}", "=".repeat(50).cyan());
    println!();
    
    // Print overall summary
    println!("{}", "Project Summary".bold());
    println!("  Files analyzed: {}", results.summary.total_files);
    println!("  Average trust score: {}", format_trust_score(results.summary.avg_score));
    println!("  Total issues found: {}", results.summary.total_issues);
    
    // Print performance metrics if available
    if results.summary.total_time_seconds > 0.0 {
        println!("  Analysis time: {:.1}s", results.summary.total_time_seconds);
        println!("  Processing speed: {:.2} files/second", results.summary.files_per_second);
    }
    
    if results.summary.files_skipped > 0 {
        println!("  Files skipped: {}", results.summary.files_skipped);
        if !results.summary.skipped_reasons.is_empty() {
            println!("  Skip reasons:");
            for (reason, count) in &results.summary.skipped_reasons {
                let reason_display = match reason.as_str() {
                    "too_large" => "Too large (>10MB)",
                    "metadata_error" => "Metadata error",
                    _ => reason,
                };
                println!("    {}: {}", reason_display, count);
            }
        }
    }
    
    println!();
    
    // Print severity breakdown
    if !results.summary.issues_by_severity.is_empty() {
        println!("{}", "Issues by Severity".bold());
        for (severity, count) in &results.summary.issues_by_severity {
            let badge = match severity.as_str() {
                "critical" => format!("🚨 {}", count).red().bold().to_string(),
                "high" => format!("⚠️ {}", count).yellow().bold().to_string(),
                "medium" => format!("ℹ️ {}", count).blue().to_string(),
                "low" => format!("💡 {}", count).green().to_string(),
                _ => format!("❓ {}", count).dimmed().to_string(),
            };
            println!("  {}: {}", severity.to_uppercase(), badge);
        }
        println!();
    }
    
    // Print per-file results
    if !results.files.is_empty() {
        println!("{}", "File Analysis Results".bold());
        println!();
        
        for file_result in &results.files {
            let trust_score = format_trust_score(file_result.trust_score);
            let file_type_str = format!("{:?}", file_result.file_type);
            let file_type = file_type_str.dimmed();
            
            println!("{} {} ({})", 
                "📄".cyan(), 
                file_result.path.display().to_string().bold(),
                file_type
            );
            println!("  Trust Score: {}", trust_score);
            
            if !file_result.issues.is_empty() {
                println!("  Issues ({}):", file_result.issues.len());
                for issue in &file_result.issues {
                    let severity_badge = format_severity_badge(&issue.severity);
                    let line_info = if let Some(line) = issue.line {
                        format!(" (line {})", line)
                    } else {
                        String::new()
                    };
                    
                    println!("    {} {}{}", 
                        severity_badge, 
                        issue.message, 
                        line_info.dimmed()
                    );
                }
            } else {
                println!("  {} No issues found", "✅".green());
            }
            println!();
        }
    }
    
    // Print overall verdict
    print_overall_verdict(results.summary.avg_score);
}

fn format_trust_score(score: u8) -> String {
    let color_score = match score {
        90..=100 => score.to_string().bright_green().to_string(),
        70..=89 => score.to_string().yellow().to_string(),
        50..=69 => score.to_string().bright_red().to_string(),
        _ => score.to_string().red().bold().to_string(),
    };
    format!("{}%", color_score)
}

fn format_severity_badge(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "🚨 CRITICAL".red().bold().to_string(),
        Severity::High => "⚠️ HIGH".yellow().bold().to_string(),
        Severity::Medium => "ℹ️ MEDIUM".blue().to_string(),
        Severity::Low => "💡 LOW".green().to_string(),
    }
}

fn print_overall_verdict(avg_score: u8) {
    println!("{}", "Overall Verdict".bold());
    match avg_score {
        90..=100 => {
            println!("{} Excellent! Your code appears to be high quality with minimal issues.",
                "🎉".green());
        },
        70..=89 => {
            println!("{} Good! Your code is generally solid but has some areas for improvement.",
                "👍".yellow());
        },
        50..=69 => {
            println!("{} Fair. Your code has several issues that should be addressed.",
                "⚠️".bright_red());
        },
        _ => {
            println!("{} Poor. Your code has significant issues that need immediate attention.",
                "❌".red().bold());
        },
    }
    println!();
}

// Port scan reporting temporarily disabled due to async networking refactor
// pub fn print_scan_report(...) { ... }