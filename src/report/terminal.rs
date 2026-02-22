use crate::{ProjectResults, Severity};
use crate::scanner::{PortScanResults, SecurityStatus, RiskLevel, ScanResult};
use crate::scanner::security_evaluator::SecurityEvaluator;
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

/// Print port scan results to terminal
pub fn print_scan_report(results: &PortScanResults, issues_only: bool) {
    println!("{}", "Vow Port Security Scan Report".bold().cyan());
    println!("{}", "=".repeat(50).cyan());
    println!();
    
    // Print scan summary
    println!("{}", "Scan Summary".bold());
    println!("  Target: {}", results.target);
    println!("  Total ports scanned: {}", results.summary.total_ports_scanned);
    println!("  Open ports found: {}", results.summary.open_ports);
    println!("  Security status:");
    println!("    {} Secure", format!("✅ {}", results.summary.secure_ports).green());
    println!("    {} Insecure", format!("❌ {}", results.summary.insecure_ports).red());
    println!("    {} Unknown/Requires Investigation", format!("❓ {}", results.summary.unknown_ports).yellow());
    println!();
    
    // Print risk summary
    if results.summary.critical_issues > 0 || results.summary.high_risk_issues > 0 {
        println!("{}", "Risk Summary".bold().red());
        if results.summary.critical_issues > 0 {
            println!("  {} Critical risk issues", format!("🚨 {}", results.summary.critical_issues).red().bold());
        }
        if results.summary.high_risk_issues > 0 {
            println!("  {} High risk issues", format!("⚠️ {}", results.summary.high_risk_issues).yellow().bold());
        }
        if results.summary.medium_risk_issues > 0 {
            println!("  {} Medium risk issues", format!("ℹ️ {}", results.summary.medium_risk_issues).blue());
        }
        if results.summary.low_risk_issues > 0 {
            println!("  {} Low risk issues", format!("💡 {}", results.summary.low_risk_issues).green());
        }
        println!();
    }
    
    // Print detailed port results
    let mut displayed_ports = Vec::new();
    
    // Group results by risk level for better presentation
    let mut critical_results = Vec::new();
    let mut high_results = Vec::new();
    let mut medium_results = Vec::new();
    let mut low_results = Vec::new();
    let mut secure_results = Vec::new();
    
    for result in &results.scan_results {
        if !result.is_open {
            continue; // Skip closed ports
        }
        
        match result.risk_level {
            RiskLevel::Critical => critical_results.push(result),
            RiskLevel::High => high_results.push(result),
            RiskLevel::Medium => medium_results.push(result),
            RiskLevel::Low => {
                if result.security_status == SecurityStatus::Secure {
                    secure_results.push(result);
                } else {
                    low_results.push(result);
                }
            }
        }
    }
    
    // Print critical issues first
    if !critical_results.is_empty() {
        println!("{}", "🚨 CRITICAL SECURITY ISSUES".red().bold().underline());
        for result in critical_results {
            print_port_detail(result);
            displayed_ports.push(result.port);
        }
        println!();
    }
    
    // Print high risk issues
    if !high_results.is_empty() {
        println!("{}", "⚠️  HIGH RISK ISSUES".yellow().bold().underline());
        for result in high_results {
            print_port_detail(result);
            displayed_ports.push(result.port);
        }
        println!();
    }
    
    // Print medium risk issues
    if !medium_results.is_empty() && !issues_only {
        println!("{}", "ℹ️  MEDIUM RISK ISSUES".blue().bold().underline());
        for result in medium_results {
            print_port_detail(result);
            displayed_ports.push(result.port);
        }
        println!();
    }
    
    // Print low risk issues
    if !low_results.is_empty() && !issues_only {
        println!("{}", "💡 LOW RISK ISSUES".green().bold().underline());
        for result in low_results {
            print_port_detail(result);
            displayed_ports.push(result.port);
        }
        println!();
    }
    
    // Print secure ports (only if not issues_only mode)
    if !secure_results.is_empty() && !issues_only {
        println!("{}", "✅ SECURE PORTS".green().bold().underline());
        for result in secure_results {
            print_port_detail(result);
            displayed_ports.push(result.port);
        }
        println!();
    }
    
    // Print overall security assessment
    let evaluator = SecurityEvaluator::new();
    let (overall_status, assessment) = evaluator.assess_overall_security(&results.scan_results);
    
    println!("{}", "Overall Security Assessment".bold().underline());
    let status_display = match overall_status {
        SecurityStatus::Secure => "✅ SECURE".green().bold().to_string(),
        SecurityStatus::RequiresInvestigation => "❓ NEEDS REVIEW".yellow().bold().to_string(),
        SecurityStatus::Insecure => "❌ INSECURE".red().bold().to_string(),
        SecurityStatus::Unknown => "❓ UNKNOWN".yellow().bold().to_string(),
    };
    println!("{}", status_display);
    println!("{}", assessment);
    println!();
    
    // Print general recommendations
    if results.summary.insecure_ports > 0 || results.summary.critical_issues > 0 {
        println!("{}", "General Security Recommendations".bold().underline());
        let recommendations = evaluator.get_general_security_recommendations();
        for (i, rec) in recommendations.iter().take(5).enumerate() {
            println!("  {}. {}", i + 1, rec);
        }
        println!();
    }
}

fn print_port_detail(result: &ScanResult) {
    let service_name = result.service.as_ref()
        .map(|s| s.name.as_str())
        .unwrap_or("Unknown");
    
    let security_badge = match result.security_status {
        SecurityStatus::Secure => "✅ SECURE".green().to_string(),
        SecurityStatus::Insecure => "❌ INSECURE".red().to_string(),
        SecurityStatus::RequiresInvestigation => "❓ REVIEW".yellow().to_string(),
        SecurityStatus::Unknown => "❓ UNKNOWN".white().to_string(),
    };
    
    let risk_badge = match result.risk_level {
        RiskLevel::Critical => "🚨 CRITICAL".red().bold().to_string(),
        RiskLevel::High => "⚠️  HIGH".yellow().bold().to_string(),
        RiskLevel::Medium => "ℹ️  MEDIUM".blue().to_string(),
        RiskLevel::Low => "💡 LOW".green().to_string(),
    };
    
    println!("  Port {}/tcp - {} {} {}", 
        result.port.to_string().bold(), 
        service_name.cyan(),
        security_badge,
        risk_badge
    );
    
    if let Some(ref service) = result.service {
        println!("    Description: {}", service.description.dimmed());
    }
    
    if let Some(ref recommendation) = result.recommendation {
        println!("    Recommendation: {}", recommendation.italic());
    }
    
    println!();
}