#Requires -Version 5.1
<#
.SYNOPSIS
    Install ctl365 from GitHub releases

.DESCRIPTION
    Run this one-liner to install ctl365 on Windows:
    irm https://raw.githubusercontent.com/ResoTech/ctl365/main/release/windows/bootstrap.ps1 | iex

.EXAMPLE
    irm https://raw.githubusercontent.com/ResoTech/ctl365/main/release/windows/bootstrap.ps1 | iex
#>

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ctl365 Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get latest release from GitHub
Write-Host "[*] Fetching latest release..." -ForegroundColor Cyan

$repo = "ResoTech/ctl365"
$releaseUrl = "https://api.github.com/repos/$repo/releases/latest"

try {
    $release = Invoke-RestMethod -Uri $releaseUrl -UseBasicParsing
    $version = $release.tag_name
    Write-Host "[OK] Latest version: $version" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to fetch release info: $_" -ForegroundColor Red
    exit 1
}

# Find Windows asset
$asset = $release.assets | Where-Object { $_.name -like "*windows*" -or $_.name -like "*win64*" -or $_.name -like "*.exe" }

if (-not $asset) {
    # Try zip files
    $asset = $release.assets | Where-Object { $_.name -like "*windows*.zip" -or $_.name -like "*win*.zip" }
}

if (-not $asset) {
    Write-Host "[ERROR] No Windows binary found in release" -ForegroundColor Red
    Write-Host "        Available assets:" -ForegroundColor Yellow
    $release.assets | ForEach-Object { Write-Host "        - $($_.name)" }
    exit 1
}

$downloadUrl = $asset.browser_download_url
$fileName = $asset.name

Write-Host "[*] Downloading $fileName..." -ForegroundColor Cyan

$tempFile = Join-Path $env:TEMP $fileName
Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing

Write-Host "[OK] Downloaded" -ForegroundColor Green

# Install location
$installDir = "$env:LOCALAPPDATA\ctl365"
New-Item -ItemType Directory -Path $installDir -Force | Out-Null

# Handle zip vs exe
if ($fileName -like "*.zip") {
    Write-Host "[*] Extracting..." -ForegroundColor Cyan
    Expand-Archive -Path $tempFile -DestinationPath $installDir -Force
    Remove-Item $tempFile -Force

    # Find the exe in extracted files
    $exe = Get-ChildItem -Path $installDir -Filter "ctl365.exe" -Recurse | Select-Object -First 1
    if ($exe -and $exe.DirectoryName -ne $installDir) {
        Move-Item $exe.FullName "$installDir\ctl365.exe" -Force
    }
} else {
    Move-Item $tempFile "$installDir\ctl365.exe" -Force
}

Write-Host "[OK] Installed to: $installDir\ctl365.exe" -ForegroundColor Green

# Add to PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$installDir;$userPath", "User")
    $env:PATH = "$installDir;$env:PATH"
    Write-Host "[OK] Added to PATH" -ForegroundColor Green
}

# Create config directory
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
