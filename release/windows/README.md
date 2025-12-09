# Windows Installation

Copy the entire ctl365 folder to your Windows machine, then:

```powershell
cd ctl365\release\windows
.\install.ps1
```

This will:
1. Install Visual Studio Build Tools if not present
2. Install Rust 1.85+ if not present
3. Build ctl365 from source
4. Install to `%LOCALAPPDATA%\ctl365`
5. Add to your PATH

Open a new terminal after installation, then run:

```powershell
ctl365 --help
ctl365 tui
```

## Uninstall

```powershell
.\uninstall.ps1
```
