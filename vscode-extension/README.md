# Vow VS Code Extension

A Visual Studio Code extension for [Vow](https://github.com/warden-ai/vow), the AI output verification engine. Detect AI-generated code, security vulnerabilities, and hallucinations directly in your editor.

## Features

### 🔍 Real-time Analysis
- **Automatic checks on save** - Run Vow analysis when files are saved (configurable)
- **Inline diagnostics** - See issues directly in your code with squiggly underlines
- **Status bar integration** - Monitor Vow status at a glance

### 🎯 Multi-Language Support
Supports analysis for 16+ programming languages:
- JavaScript, TypeScript, Python, Java, Go, Rust
- C, C++, C#, PHP, Swift, Kotlin, R, Scala
- Perl, Lua, Dart, Haskell, Ruby
- Markdown and plain text files

### 🛠 Command Palette Actions
- **Vow: Check File** - Analyze the current file
- **Vow: Check Workspace** - Analyze the entire workspace
- **Vow: Show Report** - View detailed analysis results

### ⚙️ Configurable Settings
- `vow.executablePath` - Path to Vow executable
- `vow.runOnSave` - Enable/disable automatic checks on save
- `vow.severity` - Minimum severity level to show (critical/high/medium/low)
- `vow.exclude` - Patterns to exclude from analysis

### 📊 Smart Diagnostics
- **Severity mapping** - Critical/High → Errors, Medium → Warnings, Low → Info
- **Quick fixes** - Links to Vow rule documentation
- **Precise locations** - Line and column-accurate issue reporting

## Installation

### Prerequisites
1. **Install Vow** - You need the Vow CLI tool installed on your system
   ```bash
   # Install from source (requires Rust)
   git clone https://github.com/warden-ai/vow
   cd vow
   cargo install --path .
   ```

2. **Verify installation**
   ```bash
   vow --version
   ```

### Install the Extension

#### From VSIX (Recommended)
1. Download the latest `.vsix` file from releases
2. In VS Code: `Ctrl+Shift+P` → "Extensions: Install from VSIX..."
3. Select the downloaded `.vsix` file

#### From Source
1. Clone this repository
2. Open the `vscode-extension` directory in VS Code
3. Run `npm install` to install dependencies
4. Press `F5` to launch a new Extension Development Host window

## Configuration

Open VS Code settings (`Ctrl+,`) and search for "Vow" to configure:

```json
{
  "vow.executablePath": "vow",
  "vow.runOnSave": true,
  "vow.severity": "medium",
  "vow.exclude": [
    "node_modules",
    ".git",
    "target",
    "build",
    "dist"
  ]
}
```

## Usage

### Automatic Analysis
With `vow.runOnSave` enabled (default), the extension will automatically analyze files when you save them. Issues appear as:
- **Red squiggles** for critical/high severity issues
- **Yellow squiggles** for medium severity issues  
- **Blue squiggles** for low severity issues

### Manual Analysis
Use the Command Palette (`Ctrl+Shift+P`):
- **"Vow: Check File"** - Analyze the current file
- **"Vow: Check Workspace"** - Analyze all files in the workspace
- **"Vow: Show Report"** - View detailed results in a side panel

### Status Bar
The status bar shows current Vow status:
- 🔄 **"Vow: Scanning..."** - Analysis in progress
- ✅ **"Vow: Clean"** - No issues found
- ⚠️ **"Vow: X issues"** - Issues detected
- ❓ **"Vow: Ready"** - Ready to scan

### Viewing Issues
1. **Inline diagnostics** - Hover over squiggly lines to see issue details
2. **Problems panel** - View all issues in the Problems panel (`Ctrl+Shift+M`)
3. **Report view** - Use "Vow: Show Report" for a detailed HTML report

## Troubleshooting

### Common Issues

**"Vow command not found"**
- Ensure Vow is installed and in your PATH
- Set `vow.executablePath` to the full path to the Vow executable

**"No issues detected but I expected some"**
- Check your `vow.severity` setting - you might be filtering out low-severity issues
- Verify your `vow.exclude` patterns aren't excluding files you want to check

**"Extension not activating"**
- The extension activates when you open supported file types
- Try opening a `.py`, `.js`, `.ts`, or other supported file

### Getting Help
- Check the [Vow documentation](https://github.com/warden-ai/vow)
- Report issues on the [GitHub repository](https://github.com/warden-ai/vow/issues)

## Development

### Building from Source
```bash
git clone https://github.com/warden-ai/vow
cd vow/vscode-extension
npm install
npm run compile
```

### Testing
```bash
npm test
```

### Packaging
```bash
npm install -g vsce
vsce package
```

## License

This extension is licensed under the same terms as Vow: MIT/Apache-2.0

## Contributing

Contributions are welcome! Please see the [contributing guidelines](https://github.com/warden-ai/vow/blob/main/CONTRIBUTING.md) in the main Vow repository.