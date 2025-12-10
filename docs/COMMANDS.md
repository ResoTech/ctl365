# ctl365 Command Reference

Complete reference for all **ctl365** commands.

---

## Authentication

### Login (Quick Setup)
```bash
# One-command setup - auto-creates tenant and authenticates
ctl365 login --tenant-id "YOUR-TENANT-ID" --client-id "YOUR-CLIENT-ID"
```

### Login (Existing Tenant)
```bash
ctl365 login --tenant my-tenant
```

### Login (Client Credentials for Automation)
```bash
ctl365 login \
  --tenant-id "..." \
  --client-id "..." \
  --client-secret "..." \
  --client-credentials
```

### Logout
```bash
ctl365 logout                    # Logout from current tenant
ctl365 logout --tenant <name>    # Logout from specific tenant
ctl365 logout --all              # Logout from all tenants
```

---

## Tenant Management

### Add Tenant
```bash
ctl365 tenant add <name> \
  --tenant-id "00000000-0000-0000-0000-000000000000" \
  --client-id "11111111-1111-1111-1111-111111111111" \
  --description "Production tenant"
```

### List Tenants
```bash
ctl365 tenant list               # Simple list
ctl365 tenant list --verbose     # Show auth status, expiry, etc.
```

### Switch Active Tenant
```bash
ctl365 tenant switch <name>
```

### Remove Tenant
```bash
ctl365 tenant remove <name>
```

### Configure Tenant Settings
```bash
ctl365 tenant configure          # Configure Exchange, SharePoint, Teams settings
```

---

## Baseline Management

### Generate Baselines
```bash
# Windows baselines
ctl365 baseline new windows --template basic
ctl365 baseline new windows --template oib --encryption --defender

# macOS baselines
ctl365 baseline new macos --template basic
ctl365 baseline new macos --template oib --encryption --defender

# iOS baselines
ctl365 baseline new ios --template basic --defender

# Android baselines
ctl365 baseline new android --template basic --defender
```

### Apply Baseline
```bash
ctl365 baseline apply --file baseline.json
ctl365 baseline apply --file baseline.json --group-id <group-id>
ctl365 baseline apply --file baseline.json --dry-run  # Preview without applying
```

### Export Existing Configuration
```bash
ctl365 baseline export --path ./backup/
```

### List Baselines
```bash
ctl365 baseline list
```

**Platforms:** `windows`, `macos`, `ios`, `android`
**Templates:** `basic`, `oib` (OpenIntuneBaseline)

---

## Conditional Access

### Deploy CA Policies
```bash
# Deploy all 44 CABaseline2025 policies
ctl365 ca deploy --all

# Deploy specific policy types
ctl365 ca deploy --mfa
ctl365 ca deploy --geoip-block
ctl365 ca deploy --compliant-device
ctl365 ca deploy --block-legacy-auth
ctl365 ca deploy --admin-mfa

# Deploy with options
ctl365 ca deploy --all --disable-security-defaults --exclusion-group <group-id>
ctl365 ca deploy --all --enable            # Start enabled (default is report-only)
ctl365 ca deploy --all --dry-run           # Preview without deploying
ctl365 ca deploy --all -y                  # Skip confirmation
```

### List CA Policies
```bash
ctl365 ca list
```

---

## Application Deployment

### Deploy Win32 Apps
```bash
ctl365 app deploy \
  --name "Zoom" \
  --type win32 \
  --file ./zoom.intunewin \
  --install-command "msiexec /i zoom.msi /qn" \
  --uninstall-command "msiexec /x zoom.msi /qn" \
  --group-id <group-id>
```

### Deploy Microsoft 365 Apps
```bash
ctl365 app deploy-m365 \
  --suite business \
  --architecture x64 \
  --apps word,excel,powerpoint,outlook,teams
```

### List Applications
```bash
ctl365 app list
ctl365 app list --platform windows
ctl365 app list --format json
```

### Remove Applications
```bash
ctl365 app remove <app-id>
ctl365 app remove <app-id> --assignments-only
```

---

## Windows Autopilot

### Import Devices
```bash
ctl365 autopilot import --file devices.csv
ctl365 autopilot import --file devices.csv --group-tag production
ctl365 autopilot import --file devices.csv --profile-id <profile-id>
ctl365 autopilot import --file devices.csv --dry-run
ctl365 autopilot import --file devices.csv -y   # Skip confirmation
```

### Create Deployment Profiles
```bash
ctl365 autopilot profile --name "Standard Deployment" --mode user-driven
ctl365 autopilot profile --name "Kiosk Setup" --mode self-deploying
ctl365 autopilot profile --name "Pre-provisioned" --mode white-glove --enable-white-glove
ctl365 autopilot profile --name "Hybrid" --mode user-driven --hybrid-join
ctl365 autopilot profile --name "Test" --dry-run
```

### Assign Profiles
```bash
ctl365 autopilot assign --profile-id <id> --device <serial>
ctl365 autopilot assign --profile-id <id> --group-tag production
ctl365 autopilot assign --profile-id <id> --all-devices
ctl365 autopilot assign --profile-id <id> --device <serial> --dry-run
```

### List Devices
```bash
ctl365 autopilot list
ctl365 autopilot list --group-tag production
ctl365 autopilot list --state enrolled
ctl365 autopilot list --format json
```

### Device Operations
```bash
ctl365 autopilot status <device-id>           # Check device status
ctl365 autopilot status <device-id> --show-profile
ctl365 autopilot sync                          # Sync with Intune
ctl365 autopilot delete <device-id>           # Delete device
ctl365 autopilot delete <device-id> --force   # Skip confirmation
ctl365 autopilot delete <device-id> --dry-run
```

**Modes:** `user-driven`, `self-deploying`, `white-glove`

---

## Export/Import with Assignment Migration

### Export Policies
```bash
ctl365 export export --types all -o ./export/
ctl365 export export --types compliance,configuration --include-assignments
ctl365 export export --types settings-catalog -o ./export/
```

### Import Policies
```bash
ctl365 export import --directory ./export/
ctl365 export import --directory ./export/ --create-groups
ctl365 export import --directory ./export/ --group-mapping mapping.json
ctl365 export import --directory ./export/ --dry-run
```

### Compare Tenants
```bash
ctl365 export compare --source ./tenant-a/ --target ./tenant-b/
```

**Types:** `compliance`, `configuration`, `settings-catalog`, `apps`, `all`

---

## Audit & Compliance

### Run Audits
```bash
ctl365 audit check
ctl365 audit check --baseline oib
ctl365 audit check --output html --output-file report.html
ctl365 audit check --output json --output-file report.json
```

### Drift Detection
```bash
ctl365 audit drift --baseline baseline.json
ctl365 audit drift --baseline baseline.json --detailed
ctl365 audit drift --baseline baseline.json --fix          # Auto-remediate
ctl365 audit drift --baseline baseline.json --fix --dry-run
```

### Generate Reports
```bash
ctl365 audit report --format html --output compliance.html
ctl365 audit report --format csv --output compliance.csv
ctl365 audit report --format json --output compliance.json
```

---

## GPO Migration

### Analyze GPO
```bash
ctl365 gpo analyze --backup ./gpo-backup/
ctl365 gpo analyze --backup ./gpo-backup/ --format json
```

### Convert GPO to Intune
```bash
ctl365 gpo convert --backup ./gpo-backup/ -o converted.json
ctl365 gpo convert --backup ./gpo-backup/ --dry-run
```

### Deploy Converted Policies
```bash
ctl365 gpo deploy --file converted.json
ctl365 gpo deploy --file converted.json --dry-run
```

---

## Script Deployment

### Deploy Platform Scripts
```bash
ctl365 script deploy --name "Setup Script" --file setup.ps1 --platform windows
ctl365 script deploy --name "Mac Setup" --file setup.sh --platform macos
ctl365 script deploy --name "Test" --file test.ps1 --dry-run
```

### Deploy Proactive Remediations
```bash
ctl365 script remediation \
  --name "Fix Network Settings" \
  --detection detect.ps1 \
  --remediation fix.ps1 \
  --schedule daily
```

### List Scripts
```bash
ctl365 script list
ctl365 script list --platform windows
```

---

## SharePoint Management

### Create Sites
```bash
# Communication site
ctl365 sharepoint site-create --name "Marketing" --url-name marketing

# Team site with M365 group
ctl365 sharepoint site-create --name "Project X" --url-name projectx --site-type team

# Team site without M365 group
ctl365 sharepoint site-create --name "Archive" --url-name archive --site-type team-no-group

# With options
ctl365 sharepoint site-create \
  --name "Sales Hub" \
  --url-name sales \
  --site-type communication \
  --description "Central sales resources" \
  --owners "user1@contoso.com"

# Dry run
ctl365 sharepoint site-create --name "Test" --url-name test --dry-run
```

### List & Get Sites
```bash
ctl365 sharepoint site-list
ctl365 sharepoint site-list --search "Sales"
ctl365 sharepoint site-list --format json

ctl365 sharepoint site-get --id <site-id>
```

### Manage Pages
```bash
ctl365 sharepoint page-create \
  --site-id <site-id> \
  --name "welcome" \
  --title "Welcome" \
  --layout home \
  --publish

ctl365 sharepoint page-list --site-id <site-id>
ctl365 sharepoint page-delete --site-id <site-id> --page-id <page-id>
```

### Hub Sites
```bash
ctl365 sharepoint hub-list
ctl365 sharepoint hub-set --site-id <id> --title "Intranet Hub"
ctl365 sharepoint hub-join --site-id <id> --hub-id <hub-id>
```

---

## Viva Engage Management

### Create Communities
```bash
ctl365 viva community-create --name "Engineering" --privacy public
ctl365 viva community-create \
  --name "Leadership" \
  --privacy private \
  --description "Executive comms" \
  --owners "ceo@contoso.com"

ctl365 viva community-create --name "Test" --dry-run
```

### List & Delete Communities
```bash
ctl365 viva community-list
ctl365 viva community-list --format json
ctl365 viva community-delete --id <id> -y
```

### Manage Members
```bash
ctl365 viva community-add-member --community-id <id> --user-id <user-id>
ctl365 viva community-add-member --community-id <id> --user-id <user-id> --dry-run
ctl365 viva community-remove-member --community-id <id> --user-id <user-id>
```

### Manage Roles
```bash
# Assign roles
ctl365 viva role-assign --user-id <user-id> --role network-admin
ctl365 viva role-assign --user-id <user-id> --role corporate-communicator
ctl365 viva role-assign --user-id <user-id> --role verified-admin
ctl365 viva role-assign --user-id <user-id> --role answers-admin
ctl365 viva role-assign --user-id <user-id> --role network-admin --dry-run

# List assignments
ctl365 viva role-list
ctl365 viva role-list --role corporate-communicator

# Revoke
ctl365 viva role-revoke --assignment-id <id>
```

### Viva Connections
```bash
ctl365 viva connections-home                         # Show current
ctl365 viva connections-home --site-url "https://contoso.sharepoint.com/sites/intranet"
```

---

## Copilot & AI Agents

### List Agents
```bash
ctl365 copilot agents-list
ctl365 copilot agents-list --package-type microsoft
ctl365 copilot agents-list --package-type custom
ctl365 copilot agents-list --enabled
```

### Get Agent Details
```bash
ctl365 copilot agents-get --id <agent-id>
ctl365 copilot agents-get --id <agent-id> --format json
```

### Search Content
```bash
ctl365 copilot search --query "quarterly report"
ctl365 copilot search --query "budget" --file-type xlsx
```

### Export Interactions (Compliance)
```bash
ctl365 copilot interactions-export
ctl365 copilot interactions-export --start 2025-01-01 --end 2025-12-31
ctl365 copilot interactions-export --output interactions.json
```

### Meeting Insights
```bash
ctl365 copilot meeting-insights --user-id <user-id>
```

---

## CISA SCuBA Baseline

### Run SCuBA Assessment
```bash
ctl365 scuba audit
ctl365 scuba audit --products aad,defender,exo
```

### Check Status
```bash
ctl365 scuba status
```

### View Baselines
```bash
ctl365 scuba baselines
```

---

## Interactive TUI

### Dashboard
```bash
ctl365 tui dashboard           # Full-screen dashboard
```

### Configuration Menus
```bash
ctl365 tui clients             # MSP client management
ctl365 tui configure           # Configure active tenant
ctl365 tui quick               # Quick single-setting changes
```

### Service-Specific Configuration
```bash
ctl365 tui defender            # Defender for Office 365
ctl365 tui exchange            # Exchange Online
ctl365 tui sharepoint          # SharePoint/OneDrive
ctl365 tui teams               # Microsoft Teams
```

---

## Global Options

All commands support these flags:

```bash
--verbose, -v    # Enable verbose logging
--help, -h       # Show help for command
--version, -V    # Show version
```

### Examples
```bash
ctl365 --verbose login --tenant my-tenant
ctl365 tenant list --help
ctl365 --version
```

---

## Configuration Files

### Locations
```
~/.config/ctl365/              # Linux/macOS
%LOCALAPPDATA%\ctl365\         # Windows

├── config.toml                # Global settings
├── tenants.toml               # Tenant registry
└── cache/
    └── {tenant}.token         # Cached access tokens
```

### Manual Editing

**tenants.toml:**
```toml
[[tenants]]
name = "my-tenant"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "11111111-1111-1111-1111-111111111111"
auth_type = "devicecode"
description = "Production tenant"
```

---

## Environment Variables

```bash
export CTL365_DEFAULT_TENANT="production"
export CTL365_LOG_LEVEL="debug"
export CTL365_CONFIG_DIR="~/.ctl365"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Authentication error |
| `3` | Configuration error |
| `4` | API error |

---

## See Also

- [GETTING_STARTED.md](GETTING_STARTED.md) - First-time setup
- [docs/APP_REGISTRATION.md](docs/APP_REGISTRATION.md) - Azure AD setup
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Feature testing
- [docs/rust/](docs/rust/) - Rust development documentation

---

**ctl365** - *Control your cloud. Define your baseline.*
