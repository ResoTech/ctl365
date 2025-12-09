# Windows Installation

Copy the entire ctl365 folder to your Windows machine, then:

```powershell
cd ctl365\win
.\install.ps1
```

This will:
1. Install Rust if not present
2. Build ctl365 from source
3. Install to `%LOCALAPPDATA%\ctl365`
4. Add to your PATH

Open a new terminal after installation, then run:

```powershell
ctl365 --help
ctl365 tui
```

## Uninstall

```powershell
.\uninstall.ps1
```
