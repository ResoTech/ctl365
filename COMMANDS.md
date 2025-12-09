# ctl365 Command Reference

Quick reference for all **ctl365** commands.

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

---

## Baseline Management (Phase 2 - Coming Soon)

### Generate Baselines
```bash
ctl365 baseline new windows --template openintune
ctl365 baseline new windows --template microsoft-security-baseline --version 24H2
ctl365 baseline new macos --template openintune
ctl365 baseline new ios --template openintune
ctl365 baseline new android --template openintune
```

### Apply Baseline
```bash
ctl365 baseline apply --file baseline.json
ctl365 baseline apply --file baseline.json --tenant production
ctl365 baseline apply --file baseline.json --dry-run  # Test without applying
```

### Export Existing Configuration
```bash
ctl365 baseline export --path ./backup/
ctl365 baseline export --tenant production --path ./prod-baseline/
```

### List Baselines
```bash
ctl365 baseline list
```

---

## Conditional Access (Phase 4 - Coming Soon)

### Deploy CA Policies
```bash
ctl365 ca deploy --baseline modern-2025
ctl365 ca deploy --baseline modern-2025 --mode report-only
ctl365 ca deploy --policy CAD001 --mode report-only
```

### Analyze Report-Only Policies
```bash
ctl365 ca analyze --policy CAD001 --days 7
ctl365 ca analyze --all --days 30
```

### Enable Policies (Promote from Report-Only)
```bash
ctl365 ca enable --policy CAD001
ctl365 ca enable --all --confirm
```

### Geo-Blocking
```bash
ctl365 ca block-countries --except US,CA
ctl365 ca block-countries --except US,CA,GB,AU --policy GeoBlock
```

---

## Compliance & Auditing (Phase 5 - Coming Soon)

### Run Audits
```bash
ctl365 audit --standard cis
ctl365 audit --standard scuba --products aad,defender,exo
ctl365 audit --standard openintune --platform windows
ctl365 audit --tenant production --standard cis
```

### Generate Reports
```bash
ctl365 report --format html --output compliance-report.html
ctl365 report --format json --output compliance-report.json
ctl365 report --format csv --output compliance-report.csv
```

### Drift Detection
```bash
ctl365 drift --baseline ./prod-baseline/ --tenant production
ctl365 drift --fix  # Remediate detected drift
```

---

## Application Deployment (Phase 7 - Coming Soon)

### Package Win32 Apps
```bash
ctl365 app package --installer ./zoom.msi --output ./packages/
ctl365 app package --installer ./app.exe --output ./packages/ --detection-script detect.ps1
```

### Deploy Apps
```bash
ctl365 app deploy zoom --package ./packages/zoom.intunewin --groups "All Users"
ctl365 app deploy screenconnect --package ./packages/sc.intunewin --groups "IT Team"
```

---

## SharePoint Management

### Create SharePoint Sites
```bash
# Create a communication site
ctl365 sharepoint site-create --name "Marketing Site" --url-name marketing

# Create a team site with M365 group
ctl365 sharepoint site-create --name "Project X" --url-name projectx --site-type team

# Create a team site without M365 group
ctl365 sharepoint site-create --name "Archive" --url-name archive --site-type team-no-group

# Create with options
ctl365 sharepoint site-create \
  --name "Sales Hub" \
  --url-name sales \
  --site-type communication \
  --description "Central sales resources" \
  --owners "user1@contoso.com,user2@contoso.com"

# Dry run (preview without creating)
ctl365 sharepoint site-create --name "Test Site" --url-name test --dry-run
```

### List & Get Sites
```bash
ctl365 sharepoint site-list                    # List all sites
ctl365 sharepoint site-list --search "Sales"   # Search sites
ctl365 sharepoint site-list --format json      # JSON output

ctl365 sharepoint site-get --id <site-id>
ctl365 sharepoint site-get --hostname contoso.sharepoint.com --path /sites/marketing
```

### Manage Pages
```bash
# Create pages
ctl365 sharepoint page-create \
  --site-id <site-id> \
  --name "welcome" \
  --title "Welcome to Our Team" \
  --layout home \
  --publish

# List pages
ctl365 sharepoint page-list --site-id <site-id>

# Delete pages
ctl365 sharepoint page-delete --site-id <site-id> --page-id <page-id>
```

### Hub Sites
```bash
ctl365 sharepoint hub-list                              # List all hub sites
ctl365 sharepoint hub-set --site-id <id> --title "Intranet Hub"  # Register as hub
ctl365 sharepoint hub-join --site-id <id> --hub-id <hub-id>      # Join to hub
```

---

## Viva Engage Management

### Create Communities
```bash
# Create a public community
ctl365 viva community-create --name "Engineering" --privacy public

# Create a private community with owners
ctl365 viva community-create \
  --name "Leadership Team" \
  --privacy private \
  --description "Executive communications" \
  --owners "ceo@contoso.com,cfo@contoso.com"

# Dry run
ctl365 viva community-create --name "Test" --dry-run
```

### List & Delete Communities
```bash
ctl365 viva community-list                    # List all communities
ctl365 viva community-list --format json      # JSON output
ctl365 viva community-delete --id <id> -y     # Delete (skip confirmation)
```

### Manage Community Members
```bash
ctl365 viva community-add-member --community-id <id> --user-id <user-id>
ctl365 viva community-remove-member --community-id <id> --user-id <user-id>
```

### Manage Viva Roles
```bash
# Assign roles
ctl365 viva role-assign --user-id <user-id> --role network-admin
ctl365 viva role-assign --user-id <user-id> --role corporate-communicator
ctl365 viva role-assign --user-id <user-id> --role verified-admin
ctl365 viva role-assign --user-id <user-id> --role answers-admin

# List role assignments
ctl365 viva role-list                                    # All roles
ctl365 viva role-list --role corporate-communicator      # Specific role

# Revoke role
ctl365 viva role-revoke --assignment-id <id>
```

### Viva Connections
```bash
ctl365 viva connections-home                         # Show current home site
ctl365 viva connections-home --site-url "https://contoso.sharepoint.com/sites/intranet"
```

---

## Copilot & AI Agents

### List Copilot Agents
```bash
# List all agents in catalog
ctl365 copilot agents-list

# Filter by type
ctl365 copilot agents-list --package-type microsoft   # Microsoft first-party
ctl365 copilot agents-list --package-type custom      # Organization-built
ctl365 copilot agents-list --package-type external    # Third-party

# Filter by status
ctl365 copilot agents-list --enabled      # Only enabled agents
ctl365 copilot agents-list --disabled     # Only disabled agents

# Filter by publisher
ctl365 copilot agents-list --publisher "Microsoft"
```

### Get Agent Details
```bash
ctl365 copilot agents-get --id <agent-id>
ctl365 copilot agents-get --id <agent-id> --format json
```

### Search Content
```bash
# Search OneDrive and SharePoint
ctl365 copilot search --query "quarterly report"

# Filter by file type
ctl365 copilot search --query "budget" --file-type xlsx
ctl365 copilot search --query "presentation" --file-type pptx
```

### Export Interactions (Compliance)
```bash
# Export all interactions
ctl365 copilot interactions-export

# Export with date range
ctl365 copilot interactions-export --start 2025-01-01 --end 2025-12-31

# Export to file
ctl365 copilot interactions-export --output copilot-interactions.json
```

### Meeting Insights
```bash
# Get insights for a user
ctl365 copilot meeting-insights --user-id <user-id>

# Get insights for specific meeting
ctl365 copilot meeting-insights --user-id <user-id> --meeting-id <meeting-id>
```

---

## Bulk Operations (Phase 6 - Coming Soon)

### Bulk Export
```bash
ctl365 bulk export --tenants all --path ./backups/
ctl365 bulk export --tenant production --path ./prod-backup/
```

### Bulk Import
```bash
ctl365 bulk import --source ./dev-baseline/ --target production
ctl365 bulk import --source ./baseline/ --target customer-a,customer-b,customer-c
ctl365 bulk import --source ./baseline/ --tenants all --mode replace
```

### Bulk Compare
```bash
ctl365 bulk compare --tenant1 dev --tenant2 production
ctl365 bulk compare --baseline ./reference/ --tenants all
```

### Documentation Generation
```bash
ctl365 document --tenant production --format html --output ./docs/
ctl365 document --tenant production --format markdown --output ./docs/
```

---

## Global Options

All commands support these global flags:

```bash
--verbose, -v    # Enable verbose logging
--help, -h       # Show help for command
--version, -V    # Show version
```

### Examples:
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
# Set default tenant
export CTL365_DEFAULT_TENANT="production"

# Set log level
export CTL365_LOG_LEVEL="debug"

# Set config directory
export CTL365_CONFIG_DIR="~/.ctl365"
```

---

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Authentication error
- `3` - Configuration error
- `4` - API error

---

## See Also

- [GETTING_STARTED.md](GETTING_STARTED.md) - First-time setup
- [docs/APP_REGISTRATION.md](docs/APP_REGISTRATION.md) - Azure AD setup
- [QUICKSTART.md](QUICKSTART.md) - Feature walkthrough
- [STATUS.md](STATUS.md) - Current project status

---

**ctl365** — *Control your cloud. Define your baseline.*
