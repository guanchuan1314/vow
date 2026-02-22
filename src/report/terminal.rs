use crate::{ProjectResults, Severity};
use owo_colors::OwoColorize;

/// Print results to terminal with colors and formatting
pub fn print_terminal_report(results: &ProjectResults) {
    println!("{}", "Vow Analysis Report".bold().cyan());
    println!("{}", "=".repeat(50).cyan());
    println!();
    
    // Print summary
    println!("{}", "Summary".bold());
    println!("  Files analyzed: {}", results.summary.total_files);
    println!("  Average trust score: {}", format_trust_score(results.summary.avg_score));
    println!("  Total issues: {}", results.summary.total_issues);
    println!();
    
    // Print issues by severity
    if !results.summary.issues_by_severity.is_empty() {
        println!("{}", "Issues by Severity".bold());
        for (severity, count) in &results.summary.issues_by_severity {
            let color_count = match severity.as_str() {
                "critical" => count.to_string().red().bold().to_string(),
                "high" => count.to_string().yellow().bold().to_string(),
                "medium" => count.to_string().blue().to_string(),
                "low" => count.to_string().green().to_string(),
                _ => count.to_string().white().to_string(),
            };
            println!("  {}: {}", severity.to_uppercase(), color_count);
        }
        println!();
    }
    
    // Print detailed results for each file
    if !results.files.is_empty() {
        println!("{}", "File Details".bold());
        println!();
        
        for file_result in &results.files {
            // Print file header
            let trust_score_display = format_trust_score(file_result.trust_score);
            println!("{} ({})", 
                file_result.path.display().to_string().bold(), 
                trust_score_display
            );
            
            if file_result.issues.is_empty() {
                println!("  {}", "✓ No issues found".green());
            } else {
                for issue in &file_result.issues {
                    let severity_badge = format_severity_badge(&issue.severity);
                    let line_info = if let Some(line) = issue.line {
                        format!(" (line {})", line)
                    } else {
                        String::new()
                    };
                    
                    println!("  {} {}{}", 
                        severity_badge, 
                        issue.message,
                        line_info.dimmed()
                    );
                }
            }
            println!();
        }
    }
    
    // Print overall verdict
    print_overall_verdict(results.summary.avg_score);
}

fn format_trust_score(score: u8) -> String {
    let score_str = format!("{}%", score);
    if score >= 80 {
        score_str.green().to_string()
    } else if score >= 60 {
        score_str.yellow().to_string()
    } else if score >= 40 {
        score_str.red().to_string()
    } else {
        score_str.red().bold().to_string()
    }
}

fn format_severity_badge(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "🚨 CRITICAL".red().bold().to_string(),
        Severity::High => "⚠️  HIGH".yellow().bold().to_string(),
        Severity::Medium => "ℹ️  MEDIUM".blue().to_string(),
        Severity::Low => "💡 LOW".green().to_string(),
    }
}

fn print_overall_verdict(avg_score: u8) {
    println!("{}", "Overall Verdict".bold().underline());
    
    if avg_score >= 80 {
        println!("{}", "✅ Code appears to be high quality with minimal AI-generated patterns".green().bold());
    } else if avg_score >= 60 {
        println!("{}", "⚠️  Code has some concerning patterns - review recommended".yellow().bold());
    } else if avg_score >= 40 {
        println!("{}", "❌ Code shows significant signs of AI generation or security issues".red().bold());
    } else {
        println!("{}", "🚨 Code has critical issues and likely extensive AI generation".red().bold());
    }
    
    println!();
}