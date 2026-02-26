#!/usr/bin/env python3
import re
import os

def fix_issues_in_file(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Pattern to match Issue struct creation without suggestion field
    pattern = r'issues\.push\(Issue \{\s*severity: [^}]+,\s*message: [^}]+,\s*line: [^}]+,\s*rule: [^}]+,\s*\}\);'
    
    def add_suggestion(match):
        # Extract the matched text and add suggestion field before the closing brace
        matched_text = match.group(0)
        # Insert suggestion before the closing });
        return matched_text.replace('});', 'suggestion: Some("Review and fix this issue".to_string()),\n                    });')
    
    # Apply the fix
    fixed_content = re.sub(pattern, add_suggestion, content, flags=re.MULTILINE | re.DOTALL)
    
    # Write back if changes were made
    if fixed_content != content:
        with open(file_path, 'w') as f:
            f.write(fixed_content)
        print(f"Fixed {file_path}")

# Fix all analyzer files
analyzer_dir = "src/analyzers"
for file_name in os.listdir(analyzer_dir):
    if file_name.endswith('.rs'):
        fix_issues_in_file(os.path.join(analyzer_dir, file_name))