# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2025-12-12

### Added
- **Edit Client in TUI** - Full implementation of client editing workflow
  - New `ClientEditSelect` and `ClientEdit` screens
  - Edit menu item in Client List with 'e' shortcut
  - Pre-populated form with existing client values
  - Updates both MSP config and tenant config on save
  - Audit trail for client modifications

- **SCuBA Alignment Scoring** - CISA Secure Cloud Business Applications compliance assessment
  - 6 categories assessed: Entra ID, Exchange Online, Defender for O365, SharePoint/OneDrive, Teams, Power Platform
  - 32 total checks across Microsoft 365 security baseline
  - Per-category scores and overall alignment percentage
  - Integrated into comprehensive tenant security reports

- **Windows Autopilot Management in TUI** - New dashboard section
  - List Autopilot devices with serial number, model, manufacturer, enrollment state
  - View Autopilot deployment profiles
  - Trigger Autopilot sync with Intune
  - Menu item with 'w' shortcut on dashboard

- **Applications Menu Enabled** - Mobile apps now viewable in TUI
  - Navigate via Intune > Applications in TUI
  - Lists Win32 apps, Store apps with deployment status
  - Full async loading with progress indicator

### Improved
- **Intune Settings Submenu** - Better navigation
  - Compliance Policies now navigates to policy list
  - Configuration Profiles now navigates to policy list
  - Distinct menu item IDs avoid conflict with report generators

### Technical
- New `Screen::ClientEditSelect`, `Screen::ClientEdit(String)`, `Screen::Autopilot`, `Screen::AutopilotDevices`, `Screen::AutopilotProfiles` variants
- New `TaskRequest` variants: `LoadAutopilotDevices`, `LoadAutopilotProfiles`, `SyncAutopilot`
- New `TaskResult` variants: `AutopilotDevicesLoaded`, `AutopilotProfilesLoaded`, `AutopilotSynced`
- New data types: `AutopilotDeviceData`, `AutopilotProfileData`
- Autopilot device/profile render functions with M365 Fluent Design
- Context-sensitive refresh action across all data screens
- `calculate_scuba_alignment()` function with 200+ lines of compliance logic
- All 155 tests passing
- Zero clippy warnings

## [0.1.4] - 2025-12-11

### Added
- **Security Monitoring Data Views** - Full TUI screens for viewing fetched security data
  - Sign-in Logs table with color-coded status (Success/Failure) and risk levels
  - Risky Users table showing risk level, state, and details
  - Risky Sign-ins table with timestamp, user, app, and risk info
  - Directory Audit table showing activity, category, initiator, and result
  - Security Summary dashboard with risk assessment (HIGH/MEDIUM/LOW)
  - Auto-navigation to data view after successful fetch
  - Menu with Refresh, Export, and Back options on all data screens

- **Multi-Platform Baseline Deployment in TUI**
  - macOS baseline deployment via menu (OpenIntuneBaseline v1.0)
  - iOS baseline deployment via menu
  - Android baseline deployment via menu (Work Profile + Fully Managed)
  - Confirmation dialogs with impact summaries for all platforms

### Improved
- **Conditional Access Policy Viewer** - Better error handling for permission (403) and license (404) issues
- **Security Monitoring UX** - Data screens show proper breadcrumbs and empty state messages

### Technical
- 5 new Screen variants: `SignInLogs`, `RiskyUsers`, `RiskySignIns`, `DirectoryAudit`, `SecuritySummary`
- 6 new render functions for security data visualization
- M365 Fluent Design color coding throughout security tables
- All 150 tests passing
- Zero clippy warnings

## [0.1.3] - 2025-12-11

### Added
- **Identity Protection Graph API Module** (`src/graph/identity_protection.rs`)
  - Sign-in logs API: `get_sign_in_logs()` with flexible filtering
  - Risky users API: `get_risky_users()`, `dismiss_risky_user()`, `confirm_user_compromised()`
  - Risky sign-ins API: `get_risky_sign_ins()` with risk level filtering
  - Directory audit API: `get_directory_audits()` with category/activity filtering
  - Security summary: `get_identity_protection_summary()` for dashboard view
  - Filter types: `SignInFilter`, `RiskyUserFilter`, `DirectoryAuditFilter`
  - Enums: `RiskLevel`, `RiskState`, `RiskDetail`
  - Full documentation with permission requirements

- **TUI Security Monitoring Screen**
  - New dashboard menu item: "Security Monitoring" (shortcut: `s`)
  - Sub-menu with sign-in logs, risky users, risky sign-ins, directory audit, security summary
  - Help text with keyboard shortcuts
  - Requires Entra ID P1/P2 for risk-based features

- **Mouse Scroll Wheel Support**
  - Scroll wheel now navigates menu items and policy tables
  - Works on all screens - menus use select_previous/next, tables use table_previous/next
  - Left click events captured (foundation for future click-to-select)

- **Enhanced Form Input with `tui-input`**
  - Arrow keys (Left/Right) now move cursor within text input
  - Proper unicode character handling
  - Backspace, Home, End, Ctrl+A/E all work correctly
  - Visual cursor position tracking

- **Render Throttling (10ms minimum)**
  - Prevents excessive CPU usage when many events arrive quickly
  - Inspired by yazi's event batching pattern
  - `last_render` tracking ensures minimum interval between frames

### Improved
- **TUI Status Bar** - Now shows timestamps on status messages (`[HH:MM:SS] message`)
- **PDF Export Hint** - Report success message now includes "Ctrl+P to save as PDF" tip
- **Form Input Visibility** - Fixed Windows PowerShell form input using real terminal cursor
  - Uses `frame.set_cursor_position()` instead of fake "_" character
  - Simplified styling following ratatui official patterns
- **Documentation** - Added Identity Protection permissions to `docs/PERMISSIONS.md`:
  - `AuditLog.Read.All` - Sign-in logs, directory audit
  - `IdentityRiskyUser.Read.All` - Risky users (read-only)
  - `IdentityRiskyUser.ReadWrite.All` - Dismiss/confirm risky users
  - `IdentityRiskEvent.Read.All` - Risky sign-ins
  - Added permission GUIDs to reference table

### Dependencies
- Added `tui-scrollview = "0.5"` for future scrollable content support
- Using `tui-input = "0.11"` for enhanced form input handling

### Technical
- Windows PowerShell compatible (basic ANSI colors only)
- All 141+ tests passing
- Zero clippy warnings

## [0.1.2] - 2025-12-11

### Fixed
- **Windows TUI Crash Fix** - Fixed string slicing panic on Windows PowerShell
  - Root cause: Byte-based string slicing (`get(..8)`) on non-ASCII input caused "byte index out of bounds" panic
  - Solution: Replaced with character-based truncation (`chars().take(8)`) throughout codebase
  - Affects: `login.rs` tenant/client ID display, TUI client list rendering

### TUI Hardening (Windows Terminal Stability)
- **Ctrl+C Task Cancellation** - Users can now dismiss stuck async overlays with Ctrl+C
  - Clears progress overlay and shows warning that background work may still be running
  - Prevents permanent UI lock when worker thread hangs

- **Worker Ready Gating** - Async menu actions now blocked until background worker signals ready
  - Prevents race condition where tasks could be sent before worker initialized
  - Shows "Background worker is starting up, please wait..." message if attempted too early

- **Channel Health Check** - Added proactive channel connectivity check before task submission
  - Detects disconnected worker before showing progress overlay
  - Shows "Worker connection lost - restart TUI" if channel disconnected

- **Unified Task Completion** - Refactored `process_task_responses` to use `finish_task()` helper
  - Consistent state cleanup across all task result types
  - Session change counter now increments on successful deployments
  - Eliminates code duplication in task completion paths

### Technical Improvements
- **TaskEnvelope Contract** - TUI generates task IDs, worker echoes them back (drift prevention)
- **60-Second Watchdog** - Tasks auto-dismiss with warning if no response within timeout
- **Improved Guard Rails** - `begin_task()` now checks: running task, sender exists, worker ready, channel connected

### Performance (Phase 1)
- **30fps Frame Rate Limiting** - Reduces CPU usage on idle screens
- **Dirty Flag Rendering** - Only redraws when `needs_redraw` is true
- **Virtual Scrolling** - Lists >100 items use buffer-based rendering with 5-row scroll buffer
- **Optimized Event Loop** - Dynamic poll timeout based on frame budget
- **`update_visible_rows()`** - Track visible range for smooth large-list scrolling

### Worker Resilience (Phase 2)
- **Heartbeat Monitoring** - Tracks `last_worker_response` timestamp
- **30-Second Health Timeout** - Marks worker as unhealthy after silence
- **Exponential Backoff** - Retries channel-full errors with 100ms/200ms/400ms delays
- **Channel Retry Limit** - Gives up after 3 consecutive failures

### Windows Terminal Polish (Phase 3)
- **Resize Event Handling** - Debounced terminal resize with 50ms delay
- **Event Type Filtering** - Ignores FocusGained/Lost, Mouse, Paste events
- **Panic Hook** - Restores terminal state on crash (critical for Windows)
- **Key Release Filtering** - Only processes KeyPress events

## [0.1.1] - 2025-12-10

### Added
- **Testing Infrastructure Sprint**
  - 51 new unit tests for template generators (Android, Windows OIB, CA Baseline 2025)
  - Total test count: 125 tests (112 unit + 13 integration)
  - Tests cover baseline generation, policy structure, and configuration validation

- **Logging & Observability Sprint**
  - Multi-level verbosity: `-v` (info), `-vv` (debug), `-vvv` (trace)
  - File logging: `--log-file <FILE>` writes logs to file
  - Quiet mode: `-q/--quiet` suppresses output except errors
  - Progress bar utilities in `cmd/progress.rs` for long operations

- **Professional HTML Report Template** (`cmd/report_template.rs`)
  - Resolve Technology branded reports with logo
  - Compliance scoring with letter grades (A-F)
  - Category-based score breakdown with visual bars
  - Findings section with severity badges (Critical/High/Medium/Low/Info)
  - Configuration change tracking table
  - Summary sections with card layout
  - Print-friendly CSS with page break handling
  - Full test coverage (6 tests)

- **Documentation Sprint**
  - `docs/PERMISSIONS.md` - Comprehensive Graph API permissions reference
    - Permissions by command (baseline, CA, autopilot, etc.)
    - Azure AD role requirements
    - Admin consent instructions (Portal, PowerShell, Graph)
    - Permission GUIDs for automation
  - `examples/` folder with sample files:
    - `autopilot-devices.csv` - Device import template
    - `group-mapping.json` - Tenant migration mapping
    - `windows-baseline-basic.json` - Baseline example

### Security & Hardening
- **Token Cache Permissions** - Unix file permissions now enforced:
  - Token cache files set to `0o600` (owner read/write only)
  - Config directories set to `0o700` (owner access only)
  - Protects credentials from other system users

- **Tenant Name Sanitization** - New validation and sanitization utilities:
  - `sanitize_tenant_name()` - Converts names to safe filesystem identifiers
  - `validate_tenant_name()` - Rejects invalid characters before saving
  - Prevents path traversal and injection via tenant names

- **CSV/JSON Validation Hardening** - Improved error handling for file imports:
  - Autopilot CSV import now reports row-by-row parse errors with line numbers
  - Validates required fields (serial number, hardware hash) before processing
  - All JSON parsing now includes file path in error messages
  - Graceful handling of malformed data (no panics)

### Added
- **CA Policy Blast Radius Metadata** - All 44 Conditional Access policy templates now include:
  - `blast_radius` field: `Low`, `Medium`, `High`, or `Critical` impact rating
  - `impact_summary` field: Human-readable description of business impact
  - Helps operators understand risk before deploying policies
  - Categories: Device (CAD), Location (CAL), Protocol (CAP), Risk (CAR), Service (CAS), User (CAU)

- **Graph API Pagination Helpers** - New shared utilities in `GraphClient`:
  - `get_all_pages<T>()` - Automatically follows `@odata.nextLink` for full result sets
  - `get_all_pages_beta<T>()` - Same for beta API endpoints
  - `get_pages_limited<T>()` - Paginated fetching with max page limit
  - `PaginatedResponse<T>` struct for consistent pagination handling

- **Enhanced TUI Export Help Text** - Detailed tooltips for export/report actions:
  - Policy export: explains JSON/CSV output and save location
  - Audit export: describes JSON format and compliance documentation use
  - Report types: compliance, security, inventory, change control, executive summary
  - Each description now includes output format and destination path info

- **Compliance Policy Validation** - Real validation in `validate_compliance_baseline()`:
  - Checks for scheduled actions on non-compliance
  - Windows: BitLocker, Secure Boot, Code Integrity validation
  - macOS: FileVault encryption, System Integrity Protection
  - iOS/Android: Device encryption requirements

- **TUI Unit Tests** - Comprehensive test coverage for TUI components:
  - 27 new tests covering App state, navigation, menus, progress, forms
  - Tests for empty/edge cases to prevent panics
  - Compatible with PowerShell terminal environment

- **Windows Installer Return Code Constants** - Documented constants in `package.rs`:
  - `WIN_SUCCESS` (0) - Installation successful
  - `WIN_SUCCESS_ALREADY_INSTALLED` (1707) - Already installed
  - `WIN_SOFT_REBOOT` (3010) - Soft reboot required
  - `WIN_HARD_REBOOT` (1641) - Hard reboot required
  - `WIN_RETRY_INSTALL_IN_PROGRESS` (1618) - Another install in progress

### Changed
- **TUI Export/Report Panes** - Now display real tenant data instead of placeholders:
  - Compliance reports show actual policy counts and deployment status
  - Security reports reflect real setting toggles and CA policy states
  - Executive summaries calculate scores from live data

### Fixed
- **Clippy Warnings** - All clippy warnings resolved across `tui/*` and `cmd/*` modules
- **Unused Code** - Removed unused `with_impact()` constructor that triggered too-many-arguments warning
- **Graph API Retry Error Messages** - Now include endpoint URL and HTTP method in error output
- **"Coming Soon" Menu Items** - Removed unimplemented `microsoft-baseline` and `cis` options
- **Standardized "Unknown" Defaults** - Consistent capitalization across all fallback values
- **Task Failure Messages** - Now include tenant name, task type, and actionable context

### TUI Polish Sprint (Production Hardening)
- **Panic Prevention** - Eliminated all potential runtime panics:
  - Test helper double unwrap replaced with triple fallback chain
  - Added `ConfigManager::default()` implementation for fallback scenarios
  - Array indexing replaced with safe `.get().copied().unwrap_or()` pattern
  - Division by zero guards added with `.max(1)` on all divisors
- **Windows Terminal Robustness** - Enhanced terminal state management:
  - `restore_terminal()` now idempotent and safe to call multiple times
  - Explicit cursor visibility restore for Windows terminals
  - Stdout flush ensures all escape sequences are sent
  - Improved panic hook with user-friendly error message
  - Proper cleanup on initialization failures
- **Version Strings** - Now read from `Cargo.toml` via `env!("CARGO_PKG_VERSION")`
- **Disabled Features** - "Applications" menu item marked as coming in v0.2
- **Doc Comments** - Fixed bare URL warnings in rustdoc

### Dependencies
- Requires Rust 1.88+ (for `let_chains` in wiremock dev dependency)

---

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
