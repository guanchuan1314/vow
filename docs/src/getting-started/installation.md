# Installation

Vow is distributed as a single binary with no dependencies, making installation straightforward on all supported platforms.

## Quick Install

### Download Pre-built Binaries

The easiest way to install Vow is to download a pre-built binary from our releases page:

```bash
# Linux x86_64
curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64 -o vow
chmod +x vow
sudo mv vow /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-darwin-arm64 -o vow
chmod +x vow
sudo mv vow /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-darwin-x86_64 -o vow
chmod +x vow
sudo mv vow /usr/local/bin/

# Windows
# Download vow-windows-x86_64.exe from the releases page
# Add to your PATH
```

### Verify Installation

After installation, verify Vow is working correctly:

```bash
vow --version
```

You should see output like:
```
vow 0.1.0
```

## Build from Source

If you prefer to build from source or need the latest development version:

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Git

### Build Steps

```bash
# Clone the repository
git clone https://github.com/guanchuan1314/vow.git
cd vow

# Build the release binary
cargo build --release

# The binary will be at target/release/vow
sudo cp target/release/vow /usr/local/bin/
```

### Build Options

For development builds:
```bash
cargo build  # Debug build (faster compile, slower runtime)
```

For optimized release builds:
```bash
cargo build --release  # Optimized build
```

## Package Managers

### Homebrew (macOS/Linux)

```bash
brew tap guanchuan1314/vow
brew install vow
```

### Cargo

```bash
cargo install vow
```

### Arch Linux (AUR)

```bash
yay -S vow
```

## Docker

For containerized environments:

```bash
# Run directly
docker run --rm -v $(pwd):/workspace ghcr.io/guanchuan1314/vow:latest check /workspace

# Build locally
docker build -t vow .
docker run --rm -v $(pwd):/workspace vow check /workspace
```

## First Run

After installation, download the required model files:

```bash
# Download default models (~150MB)
vow setup

# Or specify which models to download
vow setup --models code,text,security
```

Models are stored in:
- Linux: `~/.local/share/vow/models/`
- macOS: `~/Library/Application Support/vow/models/`
- Windows: `%APPDATA%\vow\models\`

## Updating

### Pre-built Binaries
Download the latest version using the same installation method.

### Homebrew
```bash
brew update && brew upgrade vow
```

### Cargo
```bash
cargo install vow --force
```

### Docker
```bash
docker pull ghcr.io/guanchuan1314/vow:latest
```

## Troubleshooting

### Permission Errors
If you get permission errors on Linux/macOS:
```bash
sudo chown $(whoami) /usr/local/bin/vow
chmod +x /usr/local/bin/vow
```

### Model Download Issues
If model downloads fail:
```bash
# Use a different mirror
vow setup --mirror cn

# Download specific models only
vow setup --models code

# Skip model validation
vow setup --no-verify
```

### Windows PATH Issues
Add Vow to your PATH:
1. Open System Properties → Environment Variables
2. Add the directory containing `vow.exe` to your PATH
3. Restart your terminal

## Next Steps

Once installed, head to the [Quick Start](quick-start.md) guide to learn basic usage.