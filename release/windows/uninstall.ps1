#Requires -Version 5.1
<#
.SYNOPSIS
    Uninstall ctl365

.DESCRIPTION
    Removes ctl365 binary and configuration files.

.PARAMETER RemoveConfig
    Also remove configuration files (~/.ctl365). Default: $false

.PARAMETER SystemWide
    Uninstall from system-wide location (requires admin)

.EXAMPLE
    .\uninstall.ps1

.EXAMPLE
    .\uninstall.ps1 -RemoveConfig
#>

[CmdletBinding()]
param(
    [switch]$RemoveConfig,
    [switch]$SystemWide
)

$ErrorActionPreference = 'Stop'

function Write-Status {
    param([string]$Message, [string]$Type = "Info")

    switch ($Type) {
        "Info"    { Write-Host "[*] " -ForegroundColor Cyan -NoNewline; Write-Host $Message }
        "Success" { Write-Host "[+] " -ForegroundColor Green -NoNewline; Write-Host $Message }
        "Warning" { Write-Host "[!] " -ForegroundColor Yellow -NoNewline; Write-Host $Message }
        "Error"   { Write-Host "[-] " -ForegroundColor Red -NoNewline; Write-Host $Message }
    }
}

function Uninstall-Ctl365 {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Yellow
    Write-Host "       ctl365 Uninstaller                      " -ForegroundColor Yellow
    Write-Host "===============================================" -ForegroundColor Yellow
    Write-Host ""

    # Determine install locations (matches install.ps1)
    $userInstallDir = "$env:LOCALAPPDATA\ctl365"
    $systemInstallDir = "$env:ProgramFiles\ctl365"

    $installDir = if ($SystemWide) { $systemInstallDir } else { $userInstallDir }

    # Check for admin if system-wide
    if ($SystemWide) {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Status "System-wide uninstallation requires administrator privileges." "Error"
            exit 1
        }
    }

    # Remove binary
    if (Test-Path $installDir) {
        Write-Status "Removing $installDir..."
        Remove-Item -Path $installDir -Recurse -Force
        Write-Status "Removed installation directory" "Success"
    }
    else {
        Write-Status "Installation directory not found: $installDir" "Warning"
    }

    # Remove from PATH
    Write-Status "Cleaning PATH..."
    $scope = if ($SystemWide) { "Machine" } else { "User" }
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", $scope)

    if ($currentPath -like "*$installDir*") {
        $newPath = ($currentPath -split ';' | Where-Object { $_ -ne $installDir }) -join ';'
        [Environment]::SetEnvironmentVariable("PATH", $newPath, $scope)
        Write-Status "Removed from PATH" "Success"
    }

    # Remove config if requested (config stored in %LOCALAPPDATA%\ctl365)
    $configDir = "$env:LOCALAPPDATA\ctl365"
    if ($RemoveConfig) {
        if (Test-Path $configDir) {
            Write-Status "Removing configuration directory: $configDir"

            $confirm = Read-Host "This will delete all tenant configurations and cached tokens. Continue? (y/N)"
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Remove-Item -Path $configDir -Recurse -Force
                Write-Status "Removed configuration directory" "Success"
            }
            else {
                Write-Status "Skipped configuration removal" "Info"
            }
        }
    }
    else {
        if (Test-Path $configDir) {
            Write-Status "Configuration preserved at: $configDir" "Info"
            Write-Status "Use -RemoveConfig to also delete configuration files" "Info"
        }
    }

    # Remove from PowerShell profile
    if (Test-Path $PROFILE) {
        $profileContent = Get-Content $PROFILE -Raw
        if ($profileContent -like "*ctl365*") {
            Write-Status "Cleaning PowerShell profile..."
            $cleanedContent = ($profileContent -split "`n" | Where-Object {
                    $_ -notlike "*ctl365*"
                }) -join "`n"
            $cleanedContent | Set-Content $PROFILE
            Write-Status "Removed ctl365 from PowerShell profile" "Success"
        }
    }

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "       Uninstallation Complete!                " -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
}

Uninstall-Ctl365
