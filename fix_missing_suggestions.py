#!/usr/bin/env python3
import re
import os

def add_missing_suggestions(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Pattern to match Issue struct creation that's missing suggestion field
    # Look for: rule: Some(...),\n});
    pattern = r'(rule: Some\([^)]+\),)\s*\n\s*\}\);'
    
    def add_suggestion(match):
        # Add the suggestion field before the closing });
        return match.group(1) + '\n                        suggestion: Some("Review and fix this issue".to_string()),\n                    });'
    
    # Apply the fix
    fixed_content = re.sub(pattern, add_suggestion, content, flags=re.MULTILINE)
    
    # Write back if changes were made
    if fixed_content != content:
        with open(file_path, 'w') as f:
            f.write(fixed_content)
        print(f"Added missing suggestions to {file_path}")

# Fix all analyzer files
analyzer_dir = "src/analyzers"
for file_name in os.listdir(analyzer_dir):
    if file_name.endswith('.rs'):
        add_missing_suggestions(os.path.join(analyzer_dir, file_name))