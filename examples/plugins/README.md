# Vow Plugin Examples

This directory contains example plugins to help you get started with Vow's plugin system.

## Plugin Structure

Each plugin should be in its own directory with the following structure:

```
my-plugin/
├── plugin.toml          # Plugin manifest
├── plugin.wasm          # WASM binary (or other entry point)
├── README.md            # Plugin documentation
└── src/                 # Source code (optional, for reference)
    └── lib.rs
```

## Plugin Manifest (plugin.toml)

Every plugin must have a `plugin.toml` file that describes the plugin:

```toml
name = "my-awesome-plugin"
version = "1.0.0"
description = "A plugin that does awesome things"
author = "Your Name <your.email@example.com>"
entry_point = "plugin.wasm"
plugin_type = "wasm"
supported_file_types = ["rs", "py", "js"]  # Optional: limit to specific file types
```

### Plugin Types

- `"wasm"`: WASM-based plugin (recommended for cross-platform compatibility)
- `"native"`: Native shared library (not yet supported)

## Plugin Interface

All plugins must implement the `VowPlugin` trait with these methods:

- `init()`: Initialize the plugin (called once when loaded)
- `rules()`: Return the rules this plugin provides
- `analyze(file_path, content)`: Analyze file content and return issues

## WASM Plugin Development

### Prerequisites

- Rust with `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
- `wasm-pack` (optional, for easier building): `cargo install wasm-pack`

### Building WASM Plugins

1. Create a new Rust library:
   ```bash
   cargo new --lib my-plugin
   cd my-plugin
   ```

2. Configure `Cargo.toml`:
   ```toml
   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   # Add your dependencies here
   ```

3. Implement the plugin interface in `src/lib.rs`:
   ```rust
   // See the example-plugin directory for a complete implementation
   ```

4. Build the WASM module:
   ```bash
   cargo build --target wasm32-unknown-unknown --release
   cp target/wasm32-unknown-unknown/release/my_plugin.wasm plugin.wasm
   ```

## Plugin Discovery

Vow looks for plugins in these locations:

1. `.vow/plugins/` in your project directory (recommended)
2. Custom directory specified with `--plugin-dir`
3. Global plugin directory (future enhancement)

## Example Usage

1. Place your plugin in `.vow/plugins/my-plugin/`
2. Run Vow normally: `vow check src/`
3. Use custom plugin directory: `vow check src/ --plugin-dir /path/to/plugins`

## Available Examples

- `simple-rule-plugin/`: Basic rule-based plugin
- `advanced-analyzer/`: More complex analysis plugin with multiple rules

## Best Practices

1. **Keep it focused**: Each plugin should have a specific purpose
2. **Handle errors gracefully**: Return meaningful error messages
3. **Document your rules**: Provide clear descriptions and fix suggestions
4. **Test thoroughly**: Test your plugin with various file types and edge cases
5. **Version carefully**: Use semantic versioning for your plugin releases

## Debugging

To debug plugin loading:

1. Use verbose mode: `vow check --verbose`
2. Check plugin manifest syntax: `toml check plugin.toml`
3. Verify WASM module: `wasmtime plugin.wasm` (if you have wasmtime installed)

## Contributing

Found a bug or want to improve the plugin system? 
Please submit an issue or pull request on our GitHub repository.