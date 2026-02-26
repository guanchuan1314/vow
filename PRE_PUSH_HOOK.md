# Vow Pre-Push Hook

The Vow pre-push hook automatically runs `vow check --diff` on the range of commits being pushed to prevent problematic code from reaching the remote repository.

## Installation

```bash
# Install pre-push hook
vow hooks install --pre-push

# Verify installation
ls -la .git/hooks/pre-push
```

## How It Works

1. **Hook Trigger**: Runs automatically before `git push` commands
2. **Commit Range Analysis**: Analyzes files changed between the local branch and remote branch
3. **Diff Mode**: Uses `vow check --diff <remote_sha>..<local_sha>` to only check changed files
4. **Threshold Check**: Blocks push if issues exceed the configured threshold
5. **Bypass Option**: Use `git push --no-verify` to skip the hook when needed

## Hook Script Logic

The pre-push hook receives push information via stdin in the format:
```
<local_ref> <local_sha> <remote_ref> <remote_sha>
```

For each push reference, the hook:

1. **Skip Deleted Branches**: Ignores branches being deleted (local_sha = all zeros)
2. **Handle New Branches**: For new branches (remote_sha = all zeros), finds the merge base with main/master branch
3. **Create Diff Range**: Constructs range as `<remote_sha>..<local_sha>` 
4. **Run Vow Check**: Executes `vow check . --diff "<range>" --quiet --format terminal`
5. **Block on Issues**: Exits with code 1 if Vow finds issues above threshold

## Special Cases

### New Branch Handling
For new branches where remote_sha is all zeros:
- Attempts to find merge base with `origin/main` or `origin/master`
- Falls back to `HEAD~10` or first commit if main branch not found
- This prevents analyzing the entire repository history

### Error Handling  
- Skips check if base commit cannot be found
- Shows warning but allows push to proceed
- Handles repositories without main/master branch gracefully

## Configuration

The hook respects your Vow configuration:
- Uses `.vow/config.yaml` settings if present
- Applies fail_threshold from config
- Honors exclude patterns and allowlists
- Uses custom rules if configured

## Example Output

### Successful Push (No Issues)
```bash
$ git push origin feature-branch
✅ No new issues found
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Writing objects: 100% (3/3), 284 bytes | 284.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0)
```

### Blocked Push (Issues Found)
```bash
$ git push origin feature-branch
⚠️ src/lib.rs - Trust Score: 65% (2 issues)
  Line 42: Use of eval() function detected
  Line 58: Hardcoded API key detected

❌ Vow found issues in files being pushed. Push blocked.
   Fix the issues above, or use 'git push --no-verify' to bypass.
   Checked commits: abc1234..def5678
```

## Bypass Options

### Temporary Bypass
```bash
# Skip hook for this push only
git push --no-verify origin feature-branch
```

### Disable Hook
```bash
# Uninstall pre-push hook
vow hooks uninstall --pre-push
```

### Adjust Threshold
```bash
# Temporarily lower threshold in .vow/config.yaml
fail_threshold: 5  # Allow up to 5 issues
```

## Integration with Existing Hooks

If you already have a pre-push hook:
- Vow automatically backs up the existing hook to `pre-push.vow-backup`
- Chains the hooks so both run (Vow first, then original)
- Uninstalling restores the original hook

## Performance Considerations

- **Diff Mode Efficiency**: Only analyzes changed files, not entire repository
- **Parallel Processing**: Uses Vow's parallel analysis for faster execution
- **Cache Utilization**: Benefits from Vow's file analysis cache
- **Network Independence**: All analysis happens locally

## Troubleshooting

### Hook Not Running
```bash
# Check if hook file exists and is executable
ls -la .git/hooks/pre-push

# Reinstall if needed
vow hooks uninstall --pre-push
vow hooks install --pre-push
```

### Permission Denied
```bash
# Make hook executable (Unix/Linux)
chmod +x .git/hooks/pre-push
```

### False Positives
```bash
# Add files to .vow/allowlist.txt
echo "src/generated/*.rs" >> .vow/allowlist.txt

# Or exclude via .vow/config.yaml
exclude:
  - "src/generated/**"
```

### Slow Performance
```bash
# Enable cache if disabled
vow check . --clear-cache  # Clear and rebuild cache

# Check .vowignore patterns
echo "target/" >> .vowignore
echo "node_modules/" >> .vowignore
```

## Comparison with Pre-Commit Hook

| Feature | Pre-Commit | Pre-Push |
|---------|------------|----------|
| **When** | Before `git commit` | Before `git push` |
| **Scope** | Staged files only | All commits in push range |
| **Use Case** | Individual developer workflow | Team/CI protection |
| **Bypass** | `git commit --no-verify` | `git push --no-verify` |
| **Performance** | Faster (fewer files) | Slower (more commits) |

## Best Practices

1. **Use Both Hooks**: Install both pre-commit and pre-push for defense in depth
2. **Team Configuration**: Commit `.vow/config.yaml` to ensure consistent team settings  
3. **CI Integration**: Use same Vow config in CI/CD pipelines
4. **Baseline Management**: Use `vow baseline create` to handle existing issues
5. **Regular Updates**: Keep Vow updated for latest security patterns

## Migration from Pre-Commit Only

```bash
# Install pre-push hook alongside existing pre-commit
vow hooks install --pre-push

# Both hooks will now protect your repository
```

This provides comprehensive protection:
- Pre-commit hook catches issues early in individual files
- Pre-push hook ensures no issues slip through across multiple commits