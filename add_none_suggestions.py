#!/usr/bin/env python3
import re
import os

def add_none_suggestions(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find Issue struct creations missing suggestion field
    # This regex finds patterns like:
    # issues.push(Issue {
    #     ...
    #     rule: Some(...),
    # });
    # And adds suggestion: None, before the });
    
    pattern = r'(issues\.push\(Issue \{[^}]*rule: Some\([^)]+\),)\s*(\n\s*\}\);)'
    
    def add_suggestion_none(match):
        return match.group(1) + '\n                        suggestion: None,' + match.group(2)
    
    fixed_content = re.sub(pattern, add_suggestion_none, content, flags=re.MULTILINE | re.DOTALL)
    
    if fixed_content != content:
        with open(file_path, 'w') as f:
            f.write(fixed_content)
        print(f"Added None suggestions to {file_path}")

# Fix all analyzer files
analyzer_dir = "src/analyzers"
for file_name in os.listdir(analyzer_dir):
    if file_name.endswith('.rs'):
        add_none_suggestions(os.path.join(analyzer_dir, file_name))