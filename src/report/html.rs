use crate::ProjectResults;

/// Print results in HTML format
pub fn print_html_report(results: &ProjectResults) -> Result<(), Box<dyn std::error::Error>> {
    let html = generate_html_report(results)?;
    println!("{}", html);
    Ok(())
}

/// Generate HTML report content
pub fn generate_html_report(results: &ProjectResults) -> Result<String, Box<dyn std::error::Error>> {
    let mut html = String::new();
    
    // HTML Header and CSS
    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vow Analysis Report</title>
    <style>
        :root {
            --bg-color: #ffffff;
            --text-color: #333333;
            --border-color: #e1e5e9;
            --card-bg: #f8f9fa;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
            --critical-color: #6f42c1;
            --header-bg: #343a40;
            --header-text: #ffffff;
        }
        
        [data-theme="dark"] {
            --bg-color: #1a1a1a;
            --text-color: #e9ecef;
            --border-color: #495057;
            --card-bg: #2d3748;
            --success-color: #40d085;
            --warning-color: #f6e05e;
            --danger-color: #fc8181;
            --info-color: #63b3ed;
            --critical-color: #b794f6;
            --header-bg: #2d3748;
            --header-text: #e9ecef;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: all 0.3s ease;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--header-bg);
            color: var(--header-text);
            padding: 2rem 0;
            margin: -20px -20px 2rem -20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }
        
        .header .subtitle {
            font-size: 1.1rem;
            opacity: 0.8;
        }
        
        .theme-toggle {
            position: absolute;
            top: 20px;
            right: 20px;
            background: none;
            border: 2px solid var(--header-text);
            color: var(--header-text);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        .theme-toggle:hover {
            background: var(--header-text);
            color: var(--header-bg);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        
        .summary-card h3 {
            font-size: 1rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.8;
            font-weight: 600;
        }
        
        .summary-card .value {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }
        
        .summary-card .label {
            font-size: 0.9rem;
            opacity: 0.7;
        }
        
        .severity-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }
        
        .severity-badge {
            display: flex;
            align-items: center;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
        }
        
        .severity-critical {
            background-color: var(--critical-color);
            color: white;
        }
        
        .severity-high {
            background-color: var(--danger-color);
            color: white;
        }
        
        .severity-medium {
            background-color: var(--warning-color);
            color: #333;
        }
        
        .severity-low {
            background-color: var(--success-color);
            color: white;
        }
        
        .severity-count {
            margin-left: auto;
            background: rgba(255,255,255,0.2);
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 700;
        }
        
        .files-section {
            margin-top: 2rem;
        }
        
        .section-title {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: var(--text-color);
            font-weight: 600;
            display: flex;
            align-items: center;
        }
        
        .section-title::before {
            content: "📁";
            margin-right: 0.5rem;
        }
        
        .file-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 1rem;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .file-card:hover {
            box-shadow: 0 2px 12px rgba(0,0,0,0.1);
        }
        
        .file-header {
            padding: 1rem 1.5rem;
            background: linear-gradient(135deg, var(--card-bg) 0%, var(--bg-color) 100%);
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .file-header:hover {
            background: var(--border-color);
        }
        
        .file-info {
            display: flex;
            align-items: center;
            flex-grow: 1;
        }
        
        .file-path {
            font-weight: 600;
            margin-right: 1rem;
            font-family: 'Monaco', 'Menlo', monospace;
        }
        
        .file-type {
            background: var(--info-color);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-right: 1rem;
        }
        
        .trust-score {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.9rem;
        }
        
        .trust-score.excellent {
            background: var(--success-color);
            color: white;
        }
        
        .trust-score.good {
            background: var(--warning-color);
            color: #333;
        }
        
        .trust-score.poor {
            background: var(--danger-color);
            color: white;
        }
        
        .collapse-indicator {
            font-size: 1.2rem;
            transition: transform 0.3s ease;
        }
        
        .file-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        
        .file-content.expanded {
            max-height: 2000px;
        }
        
        .issues-list {
            padding: 0;
        }
        
        .issue-item {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: flex-start;
        }
        
        .issue-item:last-child {
            border-bottom: none;
        }
        
        .issue-severity {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-right: 1rem;
            white-space: nowrap;
        }
        
        .issue-severity.critical {
            background: var(--critical-color);
            color: white;
        }
        
        .issue-severity.high {
            background: var(--danger-color);
            color: white;
        }
        
        .issue-severity.medium {
            background: var(--warning-color);
            color: #333;
        }
        
        .issue-severity.low {
            background: var(--success-color);
            color: white;
        }
        
        .issue-details {
            flex-grow: 1;
        }
        
        .issue-message {
            font-weight: 500;
            margin-bottom: 0.25rem;
        }
        
        .issue-meta {
            font-size: 0.85rem;
            opacity: 0.7;
            font-family: 'Monaco', 'Menlo', monospace;
        }
        
        .no-issues {
            padding: 2rem 1.5rem;
            text-align: center;
            color: var(--success-color);
            font-weight: 600;
        }
        
        .no-issues::before {
            content: "✅";
            font-size: 2rem;
            display: block;
            margin-bottom: 0.5rem;
        }
        
        .footer {
            margin-top: 3rem;
            padding: 1.5rem;
            text-align: center;
            border-top: 1px solid var(--border-color);
            font-size: 0.9rem;
            opacity: 0.7;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header {
                margin: -10px -10px 1rem -10px;
                padding: 1.5rem 0;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }
            
            .severity-stats {
                grid-template-columns: 1fr 1fr;
            }
            
            .file-info {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .file-type {
                margin: 0.5rem 0 0 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <button class="theme-toggle" onclick="toggleTheme()">🌙 Dark</button>
            <h1>🔍 Vow Analysis Report</h1>
            <div class="subtitle">Code Quality & Security Analysis</div>
        </div>
"#);

    // Generate summary section
    html.push_str(&generate_summary_html(results));
    
    // Generate files section
    html.push_str(&generate_files_html(results));
    
    // Footer and JavaScript
    html.push_str(r#"
        <div class="footer">
            <p>Generated by <strong>Vow</strong> - AI Output Verification Engine</p>
            <p>Report generated on <span id="timestamp"></span></p>
        </div>
    </div>
    
    <script>
        // Set current timestamp
        document.getElementById('timestamp').textContent = new Date().toLocaleString();
        
        // Theme toggle functionality
        function toggleTheme() {
            const body = document.body;
            const button = document.querySelector('.theme-toggle');
            
            if (body.getAttribute('data-theme') === 'dark') {
                body.removeAttribute('data-theme');
                button.textContent = '🌙 Dark';
                localStorage.setItem('vow-theme', 'light');
            } else {
                body.setAttribute('data-theme', 'dark');
                button.textContent = '☀️ Light';
                localStorage.setItem('vow-theme', 'dark');
            }
        }
        
        // Load saved theme
        const savedTheme = localStorage.getItem('vow-theme');
        if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.body.setAttribute('data-theme', 'dark');
            document.querySelector('.theme-toggle').textContent = '☀️ Light';
        }
        
        // File collapse/expand functionality
        function toggleFile(element) {
            const content = element.nextElementSibling;
            const indicator = element.querySelector('.collapse-indicator');
            
            if (content.classList.contains('expanded')) {
                content.classList.remove('expanded');
                indicator.style.transform = 'rotate(0deg)';
            } else {
                content.classList.add('expanded');
                indicator.style.transform = 'rotate(90deg)';
            }
        }
        
        // Auto-expand files with issues
        document.addEventListener('DOMContentLoaded', function() {
            const filesWithIssues = document.querySelectorAll('.file-card[data-has-issues="true"]');
            filesWithIssues.forEach(file => {
                const content = file.querySelector('.file-content');
                const indicator = file.querySelector('.collapse-indicator');
                content.classList.add('expanded');
                indicator.style.transform = 'rotate(90deg)';
            });
        });
    </script>
</body>
</html>
"#);
    
    Ok(html)
}

fn generate_summary_html(results: &ProjectResults) -> String {
    let mut html = String::new();
    
    // Summary cards
    html.push_str(r#"<div class="summary-grid">"#);
    
    // Files analyzed
    html.push_str(&format!(r#"
        <div class="summary-card">
            <h3>Files Analyzed</h3>
            <div class="value">{}</div>
            <div class="label">Total files processed</div>
        </div>
    "#, results.summary.total_files));
    
    // Trust score
    let trust_class = if results.summary.avg_score >= 90 {
        "excellent"
    } else if results.summary.avg_score >= 70 {
        "good"
    } else {
        "poor"
    };
    
    html.push_str(&format!(r#"
        <div class="summary-card">
            <h3>Average Trust Score</h3>
            <div class="value trust-score {}">{}</div>
            <div class="label">Overall code quality</div>
        </div>
    "#, trust_class, format!("{}%", results.summary.avg_score)));
    
    // Total issues
    html.push_str(&format!(r#"
        <div class="summary-card">
            <h3>Total Issues</h3>
            <div class="value">{}</div>
            <div class="label">Issues found</div>
        </div>
    "#, results.summary.total_issues));
    
    // Performance metrics if available
    if results.summary.total_time_seconds > 0.0 {
        html.push_str(&format!(r#"
            <div class="summary-card">
                <h3>Analysis Time</h3>
                <div class="value">{:.1}s</div>
                <div class="label">{:.1} files/sec</div>
            </div>
        "#, results.summary.total_time_seconds, results.summary.files_per_second));
    }
    
    html.push_str("</div>");
    
    // Severity breakdown
    if !results.summary.issues_by_severity.is_empty() {
        html.push_str(r#"<div class="severity-stats">"#);
        
        // Ensure we show all severities, even if zero
        let severities = ["critical", "high", "medium", "low"];
        for severity in severities {
            let count = results.summary.issues_by_severity.get(severity).unwrap_or(&0);
            let severity_class = severity;
            
            html.push_str(&format!(r#"
                <div class="severity-badge severity-{}">
                    {} {}
                    <span class="severity-count">{}</span>
                </div>
            "#, severity_class, get_severity_icon(severity), severity.to_uppercase(), count));
        }
        
        html.push_str("</div>");
    }
    
    html
}

fn generate_files_html(results: &ProjectResults) -> String {
    let mut html = String::new();
    
    if !results.files.is_empty() {
        html.push_str(r#"<div class="files-section"><h2 class="section-title">File Analysis Results</h2>"#);
        
        for file_result in &results.files {
            let has_issues = !file_result.issues.is_empty();
            let trust_class = if file_result.trust_score >= 90 {
                "excellent"
            } else if file_result.trust_score >= 70 {
                "good" 
            } else {
                "poor"
            };
            
            html.push_str(&format!(r#"
                <div class="file-card" data-has-issues="{}">
                    <div class="file-header" onclick="toggleFile(this)">
                        <div class="file-info">
                            <div class="file-path">{}</div>
                            <div class="file-type">{:?}</div>
                        </div>
                        <div class="trust-score {}">{}</div>
                        <div class="collapse-indicator">▶</div>
                    </div>
                    <div class="file-content">
            "#, has_issues, file_result.path.display(), file_result.file_type, trust_class, format!("{}%", file_result.trust_score)));
            
            if has_issues {
                html.push_str(r#"<div class="issues-list">"#);
                
                for issue in &file_result.issues {
                    let severity_str = format!("{:?}", issue.severity).to_lowercase();
                    let line_info = if let Some(line) = issue.line {
                        format!("Line {}", line)
                    } else {
                        "File".to_string()
                    };
                    
                    let rule_info = if let Some(ref rule) = issue.rule {
                        format!(" • Rule: {}", rule)
                    } else {
                        String::new()
                    };
                    
                    html.push_str(&format!(r#"
                        <div class="issue-item">
                            <div class="issue-severity {}">{}</div>
                            <div class="issue-details">
                                <div class="issue-message">{}</div>
                                <div class="issue-meta">{}{}</div>
                            </div>
                        </div>
                    "#, severity_str, severity_str.to_uppercase(), issue.message, line_info, rule_info));
                }
                
                html.push_str("</div>");
            } else {
                html.push_str(r#"<div class="no-issues">No issues found</div>"#);
            }
            
            html.push_str("</div></div>");
        }
        
        html.push_str("</div>");
    }
    
    html
}

fn get_severity_icon(severity: &str) -> &'static str {
    match severity {
        "critical" => "🚨",
        "high" => "⚠️",
        "medium" => "ℹ️",
        "low" => "💡",
        _ => "❓",
    }
}