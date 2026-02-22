# Vowignore File

Use `.vowignore` files to exclude files and directories from analysis.

## Basic Usage

Create a `.vowignore` file in your project root:

```
# Ignore test files
test_*.py
*_test.py

# Ignore generated code
generated/
**/proto/*.py

# Ignore dependencies
node_modules/
vendor/

# Ignore specific patterns
*.pb.py
*_pb2.py
```

## Syntax

The `.vowignore` file uses gitignore-style patterns:
- `#` for comments
- `*` for wildcards
- `**` for recursive directory matching
- `!` to negate patterns

## Multiple Vowignore Files

You can have `.vowignore` files in subdirectories:
- Project root: `.vowignore`
- Subdirectories: `subdir/.vowignore`
- Global: `~/.config/vow/ignore`

*This page is under development.*