# Vow VS Code Extension

Real-time AI output verification inside VS Code. Powered by the [Vow CLI](https://github.com/guanchuan1314/vow).

## Features

- **Real-time diagnostics** — runs `vow check` on save; issues appear as squiggly underlines with severity-mapped colors (Critical → Error, High → Warning, Medium → Info, Low → Hint)
- **Quick fixes** — apply Vow's suggested fix directly from the lightbulb menu
- **Inline ignore** — insert `// vow-ignore` comment for any finding via code action
- **Trust score** — status bar shows the average trust score after each scan
- **Output channel** — full scan logs in the dedicated "Vow" output channel
- **Configurable** — binary path, minimum severity, excluded analyzers, auto-scan toggle

## Requirements

Install the Vow CLI:

```bash
cargo install --path .   # from the vow repo root
# or put the binary on your PATH
```

Verify: `vow --version`

## Extension Settings

| Setting                  | Default   | Description                              |
|--------------------------|-----------|------------------------------------------|
| `vow.executablePath`    | `"vow"`   | Path to the `vow` binary                |
| `vow.runOnSave`         | `true`    | Run check automatically on file save     |
| `vow.minSeverity`       | `"low"`   | Minimum severity to show (low/medium/high/critical) |
| `vow.excludedAnalyzers` | `[]`      | Analyzer names to skip                   |
| `vow.exclude`           | `["node_modules",".git","target","build","dist"]` | Glob patterns to exclude |

## Commands

- **Vow: Check Current File** — analyse the active editor file
- **Vow: Check Workspace** — analyse the entire workspace
- **Vow: Show Report** — open an HTML report panel

## How It Works

1. On save (or manual trigger), the extension invokes `vow check <file> --format json`.
2. JSON output is parsed; issues become VS Code diagnostics at the correct lines.
3. The status bar updates with the trust score and issue count.
4. Code actions offer quick-fix replacements (from Vow's `suggestion` field) and `// vow-ignore` insertion.

## Development

```bash
cd vscode-extension
npm install
npm run compile   # or npm run watch
# Press F5 in VS Code to launch Extension Development Host
```

## License

MIT / Apache-2.0 — same as Vow.
