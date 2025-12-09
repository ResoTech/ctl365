# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Platform Support
- **iOS/iPadOS Baseline** - Full enterprise iOS management including:
  - Compliance policies with jailbreak detection and OS version enforcement
  - Device restrictions (App Store, iCloud, Safari, Siri controls)
  - Passcode policies with biometric support (Touch ID/Face ID)
  - Email profiles for Exchange Online
  - App Protection Policies (MAM) for data loss prevention
  - Microsoft Defender for Endpoint integration
  - Support for both `basic` and `oib` (OpenIntune) templates

- **Android Enterprise Baseline** - Comprehensive Android management with:
  - Work Profile mode (BYOD) compliance and restrictions
  - Fully Managed mode (Corporate Owned) compliance and restrictions
  - SafetyNet attestation for device integrity
  - Encryption requirements and security controls
  - App Protection Policies (MAM)
  - Email and WiFi profile configurations
  - Microsoft Defender for Endpoint integration
  - Support for both `basic` and `oib` templates

- **macOS Baseline** - Enterprise macOS management (previously implemented):
  - FileVault encryption enforcement
  - Gatekeeper and XProtect security
  - System Integrity Protection
  - Password and passcode policies
  - Support for both `basic` and `oib` templates

#### Application Deployment (`app` command)
- **Win32 App Deployment** - Deploy packaged Win32 applications (.intunewin)
  - Detection rules (registry, file system, MSI product code)
  - Install and uninstall command configuration
  - Return codes and reboot behavior
  - Minimum OS requirements
  - Assignment to groups (available, required, uninstall)

- **Microsoft 365 Apps Deployment** - Deploy and configure Office suite
  - Suite selection (business, enterprise, proplus)
  - Architecture selection (x86, x64)
  - Update channel configuration (current, monthlyEnterprise, semiAnnual)
  - App inclusion/exclusion (Word, Excel, PowerPoint, Outlook, etc.)
  - Office Configuration XML generation
  - Group assignments

- **Platform-Specific Apps**:
  - Microsoft Store app deployment (Windows)
  - iOS VPP (Volume Purchase Program) apps
  - Android Managed Google Play apps
  - Web apps and links

- **App Management**:
  - List deployed applications with filtering by platform
  - Remove applications or assignments
  - Package Win32 apps (placeholder for future .intunewin creation)

#### Windows Autopilot (`autopilot` command)
- **Device Import** - Bulk import devices via CSV
  - Hardware hash-based registration
  - Group tag assignment during import
  - Automatic profile assignment post-import
  - Device metadata (model, manufacturer)
  - Automatic sync with Intune after import

- **Deployment Profiles** - Create and manage Autopilot profiles
  - User-driven mode (standard OOBE)
  - Self-deploying mode (kiosk/shared devices)
  - White Glove mode (pre-provisioning)
  - Hybrid Azure AD Join support
  - OOBE customization (skip keyboard, privacy, EULA pages)
  - Device naming templates
  - Group assignment

- **Device Management**:
  - List Autopilot devices with filtering (group tag, enrollment state)
  - View detailed device status
  - Assign profiles to devices or groups
  - Manual sync with Intune
  - Delete devices from Autopilot

#### Enhanced Export/Import (`export` command)
- **Settings Catalog Export** - Export modern Settings Catalog policies
  - Full policy configuration export
  - Setting values and definitions
  - Integration with standard policy export

- **Assignment Migration** - Tenant-to-tenant assignment transfer
  - Group mapping strategies (manual, exact match, auto-create)
  - Assignment export with group metadata
  - Group mapping template generation
  - Cross-tenant group ID resolution

- **Import Modes**:
  - Standard import (create new policies)
  - Incremental sync (skip existing policies)
  - Update mode (overwrite existing policies)
  - Conflict resolution strategies

- **Group Management**:
  - Export groups with assignments
  - Generate group mapping templates
  - Auto-create missing groups during import
  - Validate group assignments pre-import

#### Enhanced Audit/Compliance (`audit` command)
- **Drift Detection** - Compare baseline vs actual tenant configuration
  - Missing policy detection
  - Modified policy detection (with detailed diff)
  - Extra policy detection (not in baseline)
  - Side-by-side configuration comparison
  - JSON diff output

- **Auto-Remediation** - Automatically fix drift
  - `--fix` flag to create missing policies
  - Dry-run mode to preview changes
  - Detailed remediation logging
  - Success/failure tracking

- **Compliance Scoring** - Quantitative security assessment
  - 0-100 compliance score calculation
  - Control-based scoring (passed/total)
  - Visual progress bars
  - Category-based breakdowns

- **Report Generation**:
  - HTML reports with charts and graphs
  - CSV exports for data analysis
  - JSON output for automation
  - Baseline comparison (OIB, CIS, ScubaGear, custom)

#### Conditional Access - Complete CABaseline2025
- **All 44 CA Policies Implemented** - Production-ready policies based on Kenneth van Surksum and Daniel Chronlund best practices:

  **Device/Platform Policies (13)**:
  - CAD001: Require compliant/hybrid joined Windows devices
  - CAD002: Block legacy Windows versions
  - CAD003: iOS/Android require approved app
  - CAD004: macOS require compliant devices
  - CAD005-016: Additional device and platform controls

  **Location-Based Policies (3)**:
  - CAL002: Block legacy auth from untrusted locations
  - CAL004: Block access from non-allowed countries
  - CAL011: Require MFA from untrusted locations

  **Protocol/Legacy Auth Policies (4)**:
  - CAP001: Block legacy authentication
  - CAP002: Block ActiveSync except Outlook mobile
  - CAP003: Require modern auth for IMAP/POP3
  - CAP004: Block deprecated protocols

  **Risk-Based Policies (5)**:
  - CAR001: Block high sign-in risk
  - CAR002: Require MFA for medium sign-in risk
  - CAR003: Block high user risk
  - CAR004: Require password change for medium user risk
  - CAR005: Require compliant device for any risk

  **Service-Specific Policies (8)**:
  - CAS001: Azure management requires MFA
  - CAS002: Office 365 baseline protection
  - CAS003: Exchange Online specific controls
  - CAS004-008: SharePoint, Teams, and other services

  **User-Based Policies (11)**:
  - CAU001: Require MFA for all users
  - CAU002: Block risky user sign-ins
  - CAU003: Require MFA for guest users
  - CAU004: Admin MFA enforcement
  - CAU005-011: Additional user context policies

### Changed
- **Baseline List Command** - Updated to show all implemented platforms (Windows, macOS, iOS, Android)
- **CLI Help Output** - Now includes `app` and `autopilot` commands in top-level help
- **Usage Examples** - Added platform-specific examples for all baseline types

### Technical Improvements
- Added `csv` crate dependency for Autopilot device import
- Consistent error handling across all new modules
- Improved GraphClient usage (fixed `client` vs `graph` variable naming)
- All modules follow established patterns from baseline implementation

### Dependencies Added
- `csv = "1.3"` - CSV parsing for Autopilot device imports

## [0.1.0] - Initial Release

### Added
- **Core CLI Framework** - Clap-based command-line interface with colored output
- **Authentication** - OAuth2 Device Code Flow and Client Credentials Flow
- **Multi-Tenant Management** - Add, list, switch, and remove tenant configurations
- **Token Management** - Secure caching with automatic expiration
- **Graph API Client** - Foundation for all Microsoft Graph operations
- **Windows Baseline** - OpenIntuneBaseline v3.6 with 15+ policies
  - Compliance policies (4)
  - Settings Catalog policies (11+)
  - BitLocker, Defender, Firewall, LAPS, WHfB
  - CIS-aligned with documented deviations
- **Conditional Access** - Initial CA policy deployment
- **Tenant Configuration** - Exchange, SharePoint, Teams settings
- **Export/Import** - Basic policy export and import functionality
- **Audit** - Basic compliance checking

### Infrastructure
- Rust 2024 edition
- Async runtime with Tokio
- Secure credential storage in `~/.ctl365/`
- TOML-based configuration
- Comprehensive error handling with thiserror

---

## Platform Support Matrix

| Platform | Basic Template | OIB Template | Compliance | Device Config | App Protection | Defender |
|----------|---------------|--------------|------------|---------------|----------------|----------|
| Windows  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| macOS    | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| iOS      | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Android  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## Feature Comparison: ctl365 vs My365 Baseline Builder

| Feature | ctl365 | My365 | Notes |
|---------|--------|-------|-------|
| **Platform Support** |
| Windows | ✅ | ✅ | OpenIntuneBaseline v3.6 |
| macOS | ✅ | ✅ | FileVault, Gatekeeper, SIP |
| iOS/iPadOS | ✅ | ✅ | MAM, compliance, profiles |
| Android | ✅ | ✅ | Work Profile + Fully Managed |
| **Deployment** |
| Autopilot | ✅ | ✅ | Import, profiles, assignment |
| Defender for Business | ✅ | ✅ | All platforms supported |
| App Deployment | ✅ | ❓ | Win32, M365, Store, VPP, Play |
| Conditional Access | ✅ | ✅ | 44 policies (CABaseline2025) |
| **Operations** |
| Multi-Tenant | ✅ | ✅ | MSP-focused design |
| Export/Import | ✅ | ❓ | With assignment migration |
| Drift Detection | ✅ | ❓ | Auto-remediation support |
| Compliance Scoring | ✅ | ❓ | 0-100 scoring system |
| **Automation** |
| CLI-based | ✅ | ❌ | Full CLI automation |
| Web-based | ❌ | ✅ | My365 has GUI |
| GitOps-ready | ✅ | ❓ | JSON baselines in Git |
| CI/CD integration | ✅ | ❓ | Client credentials flow |

---

## MSP Use Cases

### Standardized Onboarding
```bash
# Generate baseline for new client
ctl365 baseline new windows --template oib --encryption --defender -o client-baseline.json
ctl365 baseline new ios --template oib --defender
ctl365 baseline new android --template oib --defender

# Apply to tenant
ctl365 tenant switch client-name
ctl365 baseline apply -f client-baseline.json --group-id <all-users>

# Deploy Conditional Access
ctl365 ca deploy --baseline 2025 --report-only

# Configure Autopilot
ctl365 autopilot import -f devices.csv --group-tag client-name
ctl365 autopilot profile --name "Client Standard" --mode user-driven --enable-white-glove
```

### Compliance Auditing
```bash
# Check drift from baseline
ctl365 audit drift --baseline client-baseline.json --detailed

# Generate compliance report
ctl365 audit check --output html --output-file compliance-report.html

# Auto-fix drift
ctl365 audit drift --baseline client-baseline.json --fix
```

### Tenant Migration
```bash
# Export from source tenant
ctl365 tenant switch source-tenant
ctl365 export export --types all --include-assignments -o export/

# Import to destination tenant with group mapping
ctl365 tenant switch dest-tenant
ctl365 export import -d export/ --create-groups --group-mapping mapping.json
```

---

**Built for MSPs managing multiple Microsoft 365 tenants at scale.**
