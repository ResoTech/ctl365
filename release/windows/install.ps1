#Requires -Version 5.1
<#
.SYNOPSIS
    Install ctl365 - Microsoft 365 Baseline Automation CLI

.DESCRIPTION
    Installs Rust (if needed) and builds ctl365 from the current directory.
    Copy the ctl365 folder to your Windows machine, then run this script.

.EXAMPLE
    .\install.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ctl365 Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Find project root (release/windows -> release -> project root)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$releaseDir = Split-Path -Parent $scriptDir
$projectRoot = Split-Path -Parent $releaseDir

# Check we're in the right place
$cargoPath = Join-Path $projectRoot "Cargo.toml"
if (-not (Test-Path $cargoPath)) {
    Write-Host "[ERROR] Cargo.toml not found at $projectRoot" -ForegroundColor Red
    Write-Host "        Make sure this script is in the release/windows/ folder of the ctl365 project." -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Found project at: $projectRoot" -ForegroundColor Green

# Check for Visual Studio Build Tools (required for Rust on Windows)
Write-Host "[*] Checking for Visual Studio Build Tools..." -ForegroundColor Cyan
$hasVS = $false

# Check for link.exe in common VS locations
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsPath) {
        $hasVS = $true
        Write-Host "[OK] Found Visual Studio at: $vsPath" -ForegroundColor Green
    }
}

# Also check for standalone Build Tools
if (-not $hasVS) {
    $buildToolsPaths = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools"
    )
    foreach ($path in $buildToolsPaths) {
        if (Test-Path "$path\VC\Tools\MSVC") {
            $hasVS = $true
            Write-Host "[OK] Found Build Tools at: $path" -ForegroundColor Green
            break
        }
    }
}

if (-not $hasVS) {
    Write-Host ""
    Write-Host "[!] Visual Studio Build Tools not found!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Rust on Windows requires the MSVC linker (link.exe)." -ForegroundColor White
    Write-Host ""
    Write-Host "    Installing Build Tools now..." -ForegroundColor Cyan
    Write-Host ""

    $vsInstaller = "$env:TEMP\vs_buildtools.exe"

    Write-Host "[*] Downloading Visual Studio Build Tools..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile $vsInstaller -UseBasicParsing

    Write-Host "[*] Installing C++ Build Tools (this takes 5-10 minutes)..." -ForegroundColor Cyan
    Write-Host "    A Visual Studio installer window will open." -ForegroundColor Gray
    Write-Host ""

    # Install just the C++ build tools workload
    Start-Process -FilePath $vsInstaller -ArgumentList `
        "--quiet", "--wait", "--norestart", `
        "--add", "Microsoft.VisualStudio.Workload.VCTools", `
        "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22000", `
        "--includeRecommended" `
        -Wait

    Remove-Item $vsInstaller -Force -ErrorAction SilentlyContinue

    Write-Host "[OK] Build Tools installed" -ForegroundColor Green
    Write-Host ""
    Write-Host "[!] You may need to restart PowerShell for PATH changes." -ForegroundColor Yellow
    Write-Host ""
}

# Minimum Rust version for edition 2024
$minRustVersion = [version]"1.85.0"

# Check for Rust
Write-Host "[*] Checking for Rust 1.85+..." -ForegroundColor Cyan
$needsInstall = $true
try {
    $rustVer = & rustc --version 2>$null
    if ($rustVer -match "rustc (\d+\.\d+\.\d+)") {
        $currentVer = [version]$matches[1]
        if ($currentVer -ge $minRustVersion) {
            Write-Host "[OK] $rustVer" -ForegroundColor Green
            $needsInstall = $false
        } else {
            Write-Host "[*] Found $rustVer but need 1.85+. Updating..." -ForegroundColor Yellow
        }
    }
} catch {}

if ($needsInstall) {
    Write-Host "[*] Installing Rust 1.85+..." -ForegroundColor Yellow

    $rustupExe = "$env:TEMP\rustup-init.exe"
    Write-Host "[*] Downloading rustup from rustup.rs..." -ForegroundColor Cyan

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupExe -UseBasicParsing

    Write-Host "[*] Installing Rust (this takes a few minutes)..." -ForegroundColor Cyan
    & $rustupExe -y --default-toolchain stable

    # Add cargo to current session PATH
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

    # Verify we got the right version
    $rustVer = & rustc --version
    if ($rustVer -match "rustc (\d+\.\d+\.\d+)") {
        $currentVer = [version]$matches[1]
        if ($currentVer -lt $minRustVersion) {
            Write-Host "[ERROR] Installed $rustVer but need 1.85+. Try: rustup update" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "[OK] Installed: $rustVer" -ForegroundColor Green

    Remove-Item $rustupExe -Force -ErrorAction SilentlyContinue
}

# Build
Write-Host ""
Write-Host "[*] Building ctl365 (this takes a few minutes first time)..." -ForegroundColor Cyan

Push-Location $projectRoot
try {
    & cargo build --release

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Build failed" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

# Copy to install location
$installDir = "$env:LOCALAPPDATA\ctl365"
New-Item -ItemType Directory -Path $installDir -Force | Out-Null

$exePath = Join-Path $projectRoot "target\release\ctl365.exe"
Copy-Item $exePath "$installDir\ctl365.exe" -Force

Write-Host "[OK] Installed to: $installDir\ctl365.exe" -ForegroundColor Green

# Add to PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$installDir;$userPath", "User")
    $env:PATH = "$installDir;$env:PATH"
    Write-Host "[OK] Added to PATH" -ForegroundColor Green
}

# Create config subdirectory (config stored alongside binary in %LOCALAPPDATA%\ctl365)
$cacheDir = "$installDir\cache"
New-Item -ItemType Directory -Path $cacheDir -Force -ErrorAction SilentlyContinue | Out-Null

# Done
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Open a NEW terminal, then run:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ctl365 --help" -ForegroundColor White
Write-Host "  ctl365 tui" -ForegroundColor White
Write-Host ""
