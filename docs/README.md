# ctl365 Documentation

Welcome to the **ctl365** documentation!

---

## Getting Started

**New to ctl365?** Start here:

1. **[App Registration Setup](APP_REGISTRATION.md)** - **Start Here!**
   - Create Azure AD app registration
   - Configure Microsoft Graph permissions
   - Get your credentials (Tenant ID, Client ID)

2. **[Quick Start Guide](QUICKSTART.md)**
   - Install ctl365
   - Add your first tenant
   - Run your first baseline

3. **[Authentication Testing](../TEST_AUTHENTICATION.md)**
   - Test device code flow
   - Test client credentials flow
   - Troubleshooting auth issues

---

## Core Concepts

### Authentication Methods

**ctl365** supports two authentication methods:

| Method | Use Case | Requires Browser | Best For |
|--------|----------|------------------|----------|
| **Device Code Flow** | Interactive admin tasks | Yes | Day-to-day operations, testing |
| **Client Credentials** | Automation/CI-CD | No | Scheduled jobs, pipelines |

See: [APP_REGISTRATION.md](APP_REGISTRATION.md)

---

### Multi-Tenant Management

Manage multiple M365 tenants from a single ctl365 installation:

```bash
# Add multiple tenants
ctl365 tenant add customer-a --tenant-id ... --client-id ...
ctl365 tenant add customer-b --tenant-id ... --client-id ...

# Switch between them
ctl365 tenant switch customer-a
ctl365 tenant switch customer-b

# List all tenants
ctl365 tenant list --verbose
```

---

### Baseline Management

Deploy security baselines to your tenants:

```bash
# Generate baseline
ctl365 baseline new windows --template oib --encryption --defender

# Apply baseline
ctl365 baseline apply --file baseline.json --group-id <group-id>
ctl365 baseline apply --file baseline.json --dry-run

# Export existing config
ctl365 baseline export --path ./backup/

# List baselines
ctl365 baseline list
```

**Supported Platforms:** Windows, macOS, iOS, Android
**Templates:** `basic`, `oib` (OpenIntuneBaseline)

---

## Command Reference

### Authentication Commands

```bash
# Login to tenant (device code flow)
ctl365 login --tenant my-tenant

# Login with quick setup (auto-creates tenant config)
ctl365 login --tenant-id "..." --client-id "..."

# Login with client credentials (automation)
ctl365 login --tenant-id "..." --client-id "..." --client-secret "..." --client-credentials

# Logout from current tenant
ctl365 logout

# Logout from all tenants
ctl365 logout --all
```

---

### Tenant Management

```bash
# Add new tenant
ctl365 tenant add <name> --tenant-id "..." --client-id "..."

# Add with client secret (automation)
ctl365 tenant add <name> \
  --tenant-id "..." \
  --client-id "..." \
  --client-secret "..." \
  --client-credentials

# List all tenants
ctl365 tenant list
ctl365 tenant list --verbose  # Show auth status

# Switch active tenant
ctl365 tenant switch <name>

# Remove tenant
ctl365 tenant remove <name>

# Configure tenant services
ctl365 tenant configure
```

---

### Baseline Management

```bash
# Generate new baseline
ctl365 baseline new windows --template oib --encryption --defender
ctl365 baseline new macos --template oib --encryption --defender
ctl365 baseline new ios --template basic --defender
ctl365 baseline new android --template basic --defender

# Apply baseline to tenant
ctl365 baseline apply --file baseline.json --group-id <group-id>
ctl365 baseline apply --file baseline.json --dry-run

# Export existing config
ctl365 baseline export --path ./backup/

# List baselines
ctl365 baseline list
```

---

### Conditional Access

Deploy 44 production-ready CA policies (CABaseline2025):

```bash
# Deploy all policies
ctl365 ca deploy --all --dry-run
ctl365 ca deploy --all -y

# Deploy specific policy types
ctl365 ca deploy --mfa
ctl365 ca deploy --geoip-block
ctl365 ca deploy --compliant-device
ctl365 ca deploy --block-legacy-auth
ctl365 ca deploy --admin-mfa

# Deploy with options
ctl365 ca deploy --all --enable           # Start enabled (default: report-only)
ctl365 ca deploy --all --exclusion-group <group-id>

# List CA policies
ctl365 ca list
```

---

### Windows Autopilot

```bash
# Import devices
ctl365 autopilot import --file devices.csv --group-tag production
ctl365 autopilot import --file devices.csv --dry-run

# Create deployment profiles
ctl365 autopilot profile --name "Standard" --mode user-driven
ctl365 autopilot profile --name "Kiosk" --mode self-deploying
ctl365 autopilot profile --name "Pre-provisioned" --mode white-glove --enable-white-glove

# Assign profiles
ctl365 autopilot assign --profile-id <id> --device <serial>
ctl365 autopilot assign --profile-id <id> --group-tag production

# List and manage devices
ctl365 autopilot list --group-tag production
ctl365 autopilot status <device-id>
ctl365 autopilot sync
ctl365 autopilot delete <device-id>
```

---

### Application Deployment

```bash
# Deploy Win32 apps
ctl365 app deploy --name "Zoom" --type win32 --file ./zoom.intunewin \
  --install-command "msiexec /i zoom.msi /qn" \
  --uninstall-command "msiexec /x zoom.msi /qn"

# Deploy Microsoft 365 Apps
ctl365 app deploy-m365 --suite business --architecture x64 \
  --apps word,excel,powerpoint,outlook,teams

# List and remove apps
ctl365 app list --platform windows
ctl365 app remove <app-id>
```

---

### Export/Import with Assignment Migration

```bash
# Export policies
ctl365 export export --types all -o ./export/
ctl365 export export --types compliance,configuration --include-assignments

# Import policies
ctl365 export import --directory ./export/
ctl365 export import --directory ./export/ --create-groups
ctl365 export import --directory ./export/ --group-mapping mapping.json

# Compare tenants
ctl365 export compare --source ./tenant-a/ --target ./tenant-b/
```

---

### Audit & Compliance

```bash
# Run audits
ctl365 audit check
ctl365 audit check --baseline oib
ctl365 audit check --output html --output-file report.html

# Drift detection
ctl365 audit drift --baseline baseline.json --detailed
ctl365 audit drift --baseline baseline.json --fix --dry-run

# Generate reports
ctl365 audit report --format html --output compliance.html
```

---

### SharePoint Management

```bash
# Create sites
ctl365 sharepoint site-create --name "Marketing" --url-name marketing
ctl365 sharepoint site-create --name "Project X" --url-name projectx --site-type team

# List sites
ctl365 sharepoint site-list
ctl365 sharepoint site-get --id <site-id>

# Manage pages
ctl365 sharepoint page-create --site-id <id> --name "welcome" --title "Welcome"
ctl365 sharepoint page-list --site-id <id>

# Hub sites
ctl365 sharepoint hub-list
ctl365 sharepoint hub-set --site-id <id> --title "Intranet Hub"
ctl365 sharepoint hub-join --site-id <id> --hub-id <hub-id>
```

---

### Viva Engage Management

```bash
# Create communities
ctl365 viva community-create --name "Engineering" --privacy public
ctl365 viva community-list

# Manage members
ctl365 viva community-add-member --community-id <id> --user-id <user-id>
ctl365 viva community-remove-member --community-id <id> --user-id <user-id>

# Manage roles
ctl365 viva role-assign --user-id <user-id> --role network-admin
ctl365 viva role-list
ctl365 viva role-revoke --assignment-id <id>

# Viva Connections
ctl365 viva connections-home --site-url "https://contoso.sharepoint.com/sites/intranet"
```

---

### Copilot & AI Agents

```bash
# List agents
ctl365 copilot agents-list
ctl365 copilot agents-get --id <agent-id>

# Search content
ctl365 copilot search --query "quarterly report"

# Export interactions (compliance)
ctl365 copilot interactions-export --start 2025-01-01 --end 2025-12-31

# Meeting insights
ctl365 copilot meeting-insights --user-id <user-id>
```

---

### CISA SCuBA Baseline

```bash
# Run assessment
ctl365 scuba audit
ctl365 scuba audit --products aad,defender,exo

# Check status
ctl365 scuba status

# View baselines
ctl365 scuba baselines
```

---

### Interactive TUI

```bash
ctl365 tui dashboard       # Full-screen dashboard
ctl365 tui clients         # MSP client management
ctl365 tui configure       # Configure active tenant
ctl365 tui quick           # Quick single-setting changes
ctl365 tui defender        # Defender for Office 365
ctl365 tui exchange        # Exchange Online
ctl365 tui sharepoint      # SharePoint/OneDrive
ctl365 tui teams           # Microsoft Teams
```

---

## Configuration

### Config File Locations

```
~/.config/ctl365/              # Linux/macOS
%LOCALAPPDATA%\ctl365\         # Windows

├── config.toml                # Global settings
├── tenants.toml               # Tenant configurations
└── cache/
    ├── tenant-a.token         # Cached access tokens
    └── tenant-b.token
```

---

### Config File Format

**config.toml** (global settings):
```toml
default_tenant = "my-tenant"
current_tenant = "my-tenant"
log_level = "info"
```

**tenants.toml** (tenant registry):
```toml
[[tenants]]
name = "my-tenant"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "11111111-1111-1111-1111-111111111111"
auth_type = "devicecode"
description = "Production tenant"

[[tenants]]
name = "automation-tenant"
tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
client_id = "ffffffff-0000-1111-2222-333333333333"
client_secret = "your-secret-here"
auth_type = "clientcredentials"
```

---

## Troubleshooting

### Common Issues

**Authentication fails:**
- Check [APP_REGISTRATION.md](APP_REGISTRATION.md) for permission setup
- Verify admin consent granted
- Check tenant ID and client ID are correct

**Token expired:**
```bash
# Just login again
ctl365 login --tenant my-tenant
```

**Can't find config directory:**
```bash
# Create it manually
mkdir -p ~/.config/ctl365/cache
```

**Permission denied errors:**
- Verify Graph API permissions granted in Azure AD
- Check admin consent status
- Wait 5 minutes for permission changes to propagate

---

## Reference Materials

### Baselines & Standards

**ctl365** is built on industry-leading security frameworks:

- **OpenIntuneBaseline v3.6** - Microsoft MVP-curated baseline for Windows 11 25H2
- **CABaseline2025** - 44 Conditional Access policies by Kenneth van Surksum & Daniel Chronlund
- **CISA ScubaGear** - Government compliance baselines
- **CIS Microsoft 365 Benchmark** - Industry standard

---

### Microsoft Graph API

**ctl365** uses Microsoft Graph API to manage M365:

- [Microsoft Graph Documentation](https://learn.microsoft.com/en-us/graph/)
- [Intune Graph API](https://learn.microsoft.com/en-us/graph/api/resources/intune-graph-overview)
- [Conditional Access API](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy)

---

## Development

### Building from Source

```bash
git clone https://github.com/yourusername/ctl365
cd ctl365
cargo build --release

# Binary location:
# target/release/ctl365
```

### Running Tests

```bash
# Unit tests (requires nightly for wiremock)
cargo +nightly test

# See docs/rust/TESTING.md for details
```

---

### Project Structure

```
ctl365/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── cmd/                 # Command implementations
│   │   ├── login.rs
│   │   ├── tenant.rs
│   │   ├── baseline.rs
│   │   ├── ca.rs
│   │   ├── autopilot.rs
│   │   ├── app.rs
│   │   ├── sharepoint.rs
│   │   ├── viva.rs
│   │   ├── copilot.rs
│   │   └── ...
│   ├── graph/               # Microsoft Graph API
│   │   ├── mod.rs           # Core client with retry logic
│   │   ├── auth.rs          # OAuth2 authentication
│   │   ├── intune.rs        # Intune APIs
│   │   └── ...
│   ├── config/              # Configuration management
│   └── templates/           # Baseline templates
│       ├── windows.rs       # Windows 11 baseline
│       ├── macos.rs         # macOS baseline
│       ├── ios.rs           # iOS baseline
│       └── android.rs       # Android baseline
├── tests/                   # Integration tests
│   └── graph_client_tests.rs
├── docs/                    # Documentation (you are here!)
│   └── rust/               # Rust development docs
└── Cargo.toml              # Rust dependencies
```

---

## Contributing

Contributions welcome! See:
- **[ROADMAP.md](../ROADMAP.md)** - Project roadmap
- **[TODO.md](../TODO.md)** - Current tasks
- **GitHub Issues** - Report bugs or request features

---

## License

Copyright 2026 Resolve Technology LLC. See [LICENSE](../LICENSE) for details.

---

## Next Steps

1. **[Set up your app registration](APP_REGISTRATION.md)**
2. **[Test authentication](../TEST_AUTHENTICATION.md)**
3. **[Run your first baseline](QUICKSTART.md)**

---

**Questions?** Open an issue on GitHub or check the troubleshooting section above.

**ctl365** - *Control your cloud. Define your baseline.*
