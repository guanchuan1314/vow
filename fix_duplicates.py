#!/usr/bin/env python3
import re
import os

def remove_duplicate_suggestions(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Remove lines that contain only the generic suggestion we added
    lines = content.split('\n')
    filtered_lines = []
    
    for line in lines:
        # Skip lines that are just the generic suggestion we added
        if 'suggestion: Some("Review and fix this issue".to_string()),' in line:
            continue
        if 'suggestion: Some("Review and fix HTML structure".to_string()),' in line:
            continue
        if 'suggestion: Some("Fix type mismatch before method call".to_string()),' in line:
            continue
        filtered_lines.append(line)
    
    new_content = '\n'.join(filtered_lines)
    
    if new_content != content:
        with open(file_path, 'w') as f:
            f.write(new_content)
        print(f"Removed duplicates from {file_path}")

# Fix all analyzer files
analyzer_dir = "src/analyzers"
for file_name in os.listdir(analyzer_dir):
    if file_name.endswith('.rs'):
        remove_duplicate_suggestions(os.path.join(analyzer_dir, file_name))