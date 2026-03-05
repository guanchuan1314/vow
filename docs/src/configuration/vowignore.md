# Vowignore File

Use `.vowignore` files to exclude files and directories from analysis, similar to how `.gitignore` works for Git. This helps improve performance by skipping files that don't need verification.

## Basic Usage

Create a `.vowignore` file in your project root:

```
# Ignore test files
test_*.py
*_test.py
tests/

# Ignore generated code
generated/
**/proto/*.py
build/
dist/

# Ignore dependencies
node_modules/
vendor/
.venv/
venv/

# Ignore specific patterns
*.pb.py
*_pb2.py
*.min.js
*.bundle.js

# Ignore documentation
docs/
*.md
```

## Syntax

The `.vowignore` file uses gitignore-style patterns:
- `#` for comments (ignored lines)
- `*` for single-level wildcards
- `**` for recursive directory matching
- `!` to negate patterns (include what would otherwise be excluded)
- `/` at the end to match directories only
- `/` at the beginning for root-relative paths

### Pattern Examples

```
# Exact file name
config.json

# File extension
*.log

# Directory
logs/

# Files in any subdirectory
**/cache/*

# Negate pattern - include important configs
!important.config

# Root-relative path
/root-only-file.txt

# Multiple levels
src/**/test/**/*.py
```

## Multiple Vowignore Files

Vow supports hierarchical `.vowignore` files for granular control:

1. **Global ignore**: `~/.config/vow/ignore` - applies to all projects
2. **Project root**: `.vowignore` - applies to the entire project
3. **Subdirectories**: `subdir/.vowignore` - applies only to that subdirectory and below

### Precedence

More specific `.vowignore` files override more general ones:
- Subdirectory `.vowignore` overrides project root
- Project root `.vowignore` overrides global ignore
- Command-line `--include`/`--exclude` overrides all files

## Common Patterns

### Python Projects
```
# Python
__pycache__/
*.pyc
*.pyo
*.egg-info/
build/
dist/
.venv/
venv/

# Testing
.pytest_cache/
.coverage
htmlcov/

# Generated
*_pb2.py
*_pb2_grpc.py
```

### JavaScript/Node.js Projects
```
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Build output
build/
dist/
.next/
out/

# Generated
*.min.js
*.bundle.js
*.d.ts.map
```

### Go Projects
```
# Go build output
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary
*.test

# Output of the go coverage tool
*.out

# Vendor
vendor/
```

### General Development
```
# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS files
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Temporary files
tmp/
temp/
*.tmp
```

## Performance Impact

Using `.vowignore` effectively can significantly improve Vow's performance:

- **Faster scanning**: Skip large directories like `node_modules/`
- **Reduced memory usage**: Don't load unnecessary files
- **Better focus**: Analyze only relevant source code

### Recommended Excludes for Performance

```
# Large dependency directories
node_modules/
vendor/
.venv/
venv/

# Build artifacts
build/
dist/
target/
bin/
obj/

# Large generated files
*.min.js
*.bundle.js
*.map

# Binary files (automatically skipped, but explicit is clearer)
*.exe
*.so
*.dll
*.dylib
*.a
*.lib

# Media files
*.jpg
*.jpeg
*.png
*.gif
*.mp4
*.mp3
```

## Testing Your Patterns

You can test your `.vowignore` patterns by using the verbose flag:

```bash
# See which files are being analyzed
vow check . --verbose

# Check a specific pattern
vow check . --exclude "test_*" --verbose
```

## Best Practices

1. **Start simple**: Begin with common patterns and add specific ones as needed
2. **Use comments**: Document why certain patterns are excluded
3. **Test regularly**: Verify your patterns aren't excluding important files
4. **Version control**: Commit `.vowignore` files to share patterns with your team
5. **Performance first**: Prioritize excluding large directories and generated files