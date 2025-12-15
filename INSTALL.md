# Installation

## Windows (Recommended)

Run this command in PowerShell:

```powershell
irm https://raw.githubusercontent.com/ResoTech/ctl365/main/release/windows/bootstrap.ps1 | iex
```

This will:
- Download the latest release from GitHub
- Install to `%LOCALAPPDATA%\ctl365`
- Add to your PATH

Open a **new terminal** after installation, then run:
```powershell
ctl365 --help
```

---

## Linux / macOS

### From Source

```bash
# Clone and build
git clone https://github.com/ResoTech/ctl365.git
cd ctl365
cargo build --release

# Install
sudo cp target/release/ctl365 /usr/local/bin/
```

### Requirements

- Rust 1.85+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

---

## Verify Installation

```bash
ctl365 --version
ctl365 --help
```

## Next Steps

1. [Register an Azure AD App](docs/APP_REGISTRATION.md)
2. [Getting Started Guide](GETTING_STARTED.md)
