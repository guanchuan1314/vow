# Simple Rule Plugin Example

This is a basic example plugin that demonstrates how to create custom rules for Vow.

## What it does

This plugin provides a simple rule that detects potential security issues:

- **TODO comments**: Flags TODO comments that might indicate incomplete security implementations
- **Hardcoded secrets**: Detects simple patterns that might be hardcoded API keys or passwords
- **Debug logging**: Identifies debug logging statements that might leak sensitive information

## Files

- `plugin.toml` - Plugin manifest with metadata
- `plugin.wasm` - Compiled WASM binary (you need to build this)
- `src/lib.rs` - Rust source code for the plugin
- `Cargo.toml` - Rust project configuration

## Building

To build this plugin:

1. Install Rust and add the WASM target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. Build the WASM module:
   ```bash
   cargo build --target wasm32-unknown-unknown --release
   cp target/wasm32-unknown-unknown/release/simple_rule_plugin.wasm plugin.wasm
   ```

## Installation

1. Copy the entire `simple-rule-plugin/` directory to your project's `.vow/plugins/` directory:
   ```bash
   mkdir -p .vow/plugins/
   cp -r examples/plugins/simple-rule-plugin/ .vow/plugins/
   ```

2. Run Vow to see the plugin in action:
   ```bash
   vow check src/
   ```

## Customization

You can customize the rules by modifying `src/lib.rs` and rebuilding the WASM module. The plugin provides:

- Pattern-based rules (regex, contains, starts_with, ends_with)
- Configurable severity levels
- Custom fix suggestions
- File type filtering

## Example Output

When this plugin detects issues, you'll see output like:

```
⚠️  [MEDIUM] Potential hardcoded secret detected (simple-rule-plugin)
   --> src/main.rs:15
   |  let api_key = "sk-1234567890abcdef";
   |  
   |  💡 Consider using environment variables or a secure configuration file

📋 [LOW] TODO comment found (simple-rule-plugin)  
   --> src/auth.rs:42
   |  // TODO: implement proper authentication
   |
   |  💡 Complete the implementation or create a proper issue to track this work
```

## Plugin Interface

This example implements the standard Vow plugin interface:

```rust
pub trait VowPlugin {
    fn init(&mut self) -> Result<(), PluginError>;
    fn rules(&self) -> Result<Vec<PluginRule>, PluginError>;
    fn analyze(&self, file_path: &Path, content: &str) -> Result<Vec<Issue>, PluginError>;
    fn metadata(&self) -> &PluginManifest;
}
```

See the source code for the complete implementation.