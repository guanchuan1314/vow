#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, '.')

from src.analyzers.code import CodeAnalyzer
from pathlib import Path

content = """
// Comments should not trigger false positives
// This comment mentions arr.flatmap() but shouldn't be flagged

/* 
 * Multi-line comment with arr.append() example
 * should also not be flagged
 */

// String literals containing method names should not be flagged
const message = "Use arr.push() instead of arr.append()";
console.log("The flatmap method doesn't exist");

// Template literals
const template = `
    The method arr.contains() doesn't exist in JavaScript.
    Use arr.includes() instead.
`;
"""

analyzer = CodeAnalyzer.new()
result = analyzer.analyze(Path("test.js"), content)

print(f"Total issues: {len(result.issues)}")
for issue in result.issues:
    if issue.rule in ["hallucinated_signature", "nonexistent_method"]:
        print(f"Issue: {issue.message} (Rule: {issue.rule}, Line: {issue.line})")