# DIFF MODE Documentation

This document describes the new `--diff` flag added to the `vow check` command for incremental analysis of changed files.

## Usage

```bash
# Analyze unstaged changes (default)
vow check --diff

# Analyze staged changes  
vow check --diff staged

# Analyze unstaged changes explicitly
vow check --diff unstaged

# Analyze specific commit range
vow check --diff HEAD~3..HEAD
vow check --diff abc123..def456
```

## How it works

1. **Git Integration**: Uses `git diff --name-only` to get list of changed files
2. **File Filtering**: Only includes supported file types (same as regular analysis)
3. **Pipeline Integration**: Passes filtered files to existing analysis pipeline
4. **Compatible**: Works with all existing flags like `--format`, `--ci`, `--verbose`, etc.

## Examples

```bash
# Get JSON output of changed files
vow check --diff --format json

# Analyze staged changes with verbose output
vow check --diff staged --verbose

# CI mode with diff analysis
vow check --diff --ci

# Analyze changes in a specific commit range
vow check --diff HEAD~2..HEAD --format sarif
```

## Error Handling

- **Not in git repo**: Shows clear error message
- **Invalid commit range**: Validates and rejects malformed ranges  
- **No changed files**: Shows success message when no files to analyze
- **Incompatible modes**: Prevents use with `--hook-mode` or stdin input

## Performance

- Only analyzes changed files, significantly faster than full project analysis
- Useful for incremental CI/CD pipelines and pre-commit hooks
- Maintains full analysis quality on subset of files

## Implementation

- Added `src/diff.rs` module for git operations
- Integrated into main `check_input` function
- Comprehensive test coverage for git operations and edge cases
- Graceful error handling for all failure scenarios