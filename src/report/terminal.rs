use owo_colors::OwoColorize;
use crate::RuleResults;

/// Print a beautiful terminal report with trust score box
pub fn print_terminal_report(results: &RuleResults) {
    let passed_checks = results.checks.iter().filter(|c| c.passed).count();
    let failed_checks = results.checks.len() - passed_checks;
    
    // File name (placeholder)
    let file_name = "analyzed_file.py";
    
    // Trust score color based on score
    let score_color = match results.trust_score {
        90..=100 => owo_colors::AnsiColors::BrightGreen,
        70..=89 => owo_colors::AnsiColors::Yellow,
        50..=69 => owo_colors::AnsiColors::BrightYellow,
        _ => owo_colors::AnsiColors::Red,
    };
    
    // Print header
    println!();
    println!("{}", "╭─────────────────────────────────────────────╮".bright_blue());
    println!("{} {} {}", 
        "│".bright_blue(), 
        "Vow Verification Report".bright_white().bold(), 
        "│".bright_blue()
    );
    println!("{}", "├─────────────────────────────────────────────┤".bright_blue());
    
    // File info
    println!("{} {}: {:<30} {}", 
        "│".bright_blue(),
        "File".bright_cyan(),
        file_name.white(),
        "│".bright_blue()
    );
    
    // Trust score
    println!("{} {}: {:<30} {}", 
        "│".bright_blue(),
        "Trust Score".bright_cyan(),
        format!("{}%", results.trust_score).color(score_color).bold(),
        "│".bright_blue()
    );
    
    println!("{}", "├─────────────────────────────────────────────┤".bright_blue());
    
    // Checks section
    println!("{} {} {}", 
        "│".bright_blue(), 
        "Verification Checks:".bright_white().bold(), 
        "                      │".bright_blue()
    );
    
    for check in &results.checks {
        let status_icon = if check.passed { "✓".green().to_string() } else { "✗".red().to_string() };
        let status_text = if check.passed { "PASS".green().to_string() } else { "FAIL".red().to_string() };
        
        println!("{} {} {:<25} {} {}", 
            "│".bright_blue(),
            status_icon,
            check.name.white(),
            status_text,
            "│".bright_blue()
        );
    }
    
    println!("{}", "├─────────────────────────────────────────────┤".bright_blue());
    
    // Summary
    println!("{} {}: {:<3} {}: {:<3} {}: {:<3} {}", 
        "│".bright_blue(),
        "Total".bright_cyan(), results.checks.len(),
        "Passed".green(), passed_checks,
        "Failed".red(), failed_checks,
        "│".bright_blue()
    );
    
    println!("{}", "╰─────────────────────────────────────────────╯".bright_blue());
    
    // Overall status message
    println!();
    if failed_checks == 0 {
        println!("{} All checks passed! This output appears trustworthy.", "✅".green());
    } else if results.trust_score >= 70 {
        println!("{} Some issues found, but overall score is acceptable.", "⚠️".yellow());
    } else {
        println!("{} Multiple issues detected. Please review carefully.", "❌".red());
    }
    
    println!();
}