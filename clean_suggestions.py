#!/usr/bin/env python3
import re
import os

def clean_duplicates_in_file(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Pattern to find duplicate suggestion lines
    pattern = r'(\s+suggestion: [^,]+,)\s+suggestion: Some\("Review and fix this issue"\.to_string\(\)\),'
    
    def remove_duplicate(match):
        # Keep only the first suggestion
        return match.group(1)
    
    # Remove duplicate suggestion fields
    fixed_content = re.sub(pattern, remove_duplicate, content, flags=re.MULTILINE)
    
    # Write back if changes were made
    if fixed_content != content:
        with open(file_path, 'w') as f:
            f.write(fixed_content)
        print(f"Cleaned {file_path}")

# Clean all analyzer files
analyzer_dir = "src/analyzers"
for file_name in os.listdir(analyzer_dir):
    if file_name.endswith('.rs'):
        clean_duplicates_in_file(os.path.join(analyzer_dir, file_name))