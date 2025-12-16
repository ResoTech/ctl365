# Quick Start Guide - ctl365

## Current Features

ctl365 is a full-featured M365 management CLI with TUI dashboard. Here's what's available:

### Authentication & Multi-Tenant Management

- **Microsoft Graph Authentication**
  - Device code flow (interactive login)
  - Client credentials flow (non-interactive)
  - Secure token caching in `~/.ctl365/`

- **Multi-Tenant Management**
  - Add/list/switch/remove tenants
  - Per-tenant authentication
  - Easy tenant switching

### Security Baselines & Conditional Access

- **CA Baseline 2025** - 46 production-ready Conditional Access policies
  - Deploy all or filter by category (CAD/CAL/CAP/CAR/CAS/CAU)
  - Blast radius warnings (Critical/High/Medium/Low)
  - Report-only mode by default for safety

- **Windows/macOS/iOS/Android Baselines** - Intune device configuration templates

- **CA Policy Management**
  - `ca list` - View all CA policies with state
  - `ca deploy --baseline 2025` - Deploy CA Baseline 2025 policies
  - `ca enable` / `ca disable` - Toggle policies with audit trail

### TUI Dashboard (Primary Interface)

- **Interactive Security Monitoring** - Real-time tenant security overview
- **Generate Full Security Report** - HTML report with grade (A-F), compliance score, MFA status, CA coverage
- **Multi-tenant switching** - Manage all your tenants from one interface

### Additional Features

- **Audit & Compliance** - Drift detection, compliance reporting
- **App Deployment** - Intune application management
- **Autopilot** - Windows Autopilot device management
- **GPO Migration** - Convert GPOs to Intune policies
- **SCuBA Assessment** - CISA baseline compliance checking
- **SharePoint/Viva/Copilot** - M365 workload management

---

## Installation

### Build from Source

```bash
cd /data/lab/ctl365
cargo build --release

# Binary location:
# target/x86_64-unknown-linux-gnu/release/ctl365
```

### Quick Test

```bash
./target/x86_64-unknown-linux-gnu/release/ctl365 --help
```

---

## Usage Examples

### 1. Add Your First Tenant

You'll need:
- **Tenant ID**: Your Azure AD tenant ID (found in Azure Portal)
- **Client ID**: Application (client) ID from your Azure AD app registration

> **Client Identifier**: Each tenant you add gets a short 4-character identifier that you choose. This is how you'll reference the client in all commands. For MSPs managing multiple customers, use memorable codes like `ACME`, `BOWL`, `CORP`, `CNTO`. Keep it short - you'll type it often.

#### Option A: Interactive Login (Device Code Flow)

```bash
ctl365 tenant add ACME \
  --tenant-id "00000000-0000-0000-0000-000000000000" \
  --client-id "11111111-1111-1111-1111-111111111111"
```

#### Option B: Client Credentials (Non-Interactive)

```bash
ctl365 tenant add ACME \
  --tenant-id "00000000-0000-0000-0000-000000000000" \
  --client-id "11111111-1111-1111-1111-111111111111" \
  --client-secret "your-client-secret" \
  --client-credentials
```

### 2. Login to Microsoft Graph

```bash
# Login to the tenant you just added
ctl365 login ACME
```

This will:
1. Open a browser prompt (device code flow)
2. Ask you to visit https://microsoft.com/devicelogin
3. Enter the code displayed
4. Save your access token securely to `~/.ctl365/cache/ACME.token`

### 3. Manage Multiple Tenants

```bash
# List all configured tenants
ctl365 tenant list

# List with detailed info (shows auth status)
ctl365 tenant list --detailed

# Add another tenant
ctl365 tenant add CNTO \
  --tenant-id "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" \
  --client-id "ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj"

# Switch active tenant
ctl365 tenant switch CNTO

# Login to the new tenant
ctl365 login --tenant CNTO
```

### 4. Logout

```bash
# Logout from current tenant
ctl365 logout

# Logout from specific tenant
ctl365 logout --tenant ACME

# Logout from all tenants
ctl365 logout --all
```

---

## Azure AD App Registration Setup

To use ctl365, you need to register an application in Azure AD:

### 1. Register the App

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Name: `ctl365` (or your preference)
5. Supported account types: **Accounts in this organizational directory only**
6. Click **Register**

### 2. Configure API Permissions

Add the following **Microsoft Graph** permissions (Application type):

- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementApps.ReadWrite.All`
- `DeviceManagementManagedDevices.ReadWrite.All`
- `Directory.ReadWrite.All`
- `Policy.ReadWrite.ConditionalAccess`

**Important**: Click **Grant admin consent** after adding permissions!

### 3. Get Your Credentials

#### For Device Code Flow (Interactive):
- Copy the **Application (client) ID**
- Copy your **Directory (tenant) ID**

#### For Client Credentials Flow (Non-Interactive):
- Go to **Certificates & secrets**
- Click **New client secret**
- Copy the secret value immediately (it won't be shown again!)

---

## Configuration Files

All configuration is stored in `~/.ctl365/`:

```
~/.ctl365/
├── config.toml          # Global settings
├── tenants.toml         # Tenant configurations
└── cache/
    └── ACME.token       # Cached access tokens (per client)
```

### Example `tenants.toml`:

```toml
[[tenants]]
name = "ACME"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "11111111-1111-1111-1111-111111111111"
auth_type = "devicecode"
description = "Acme Corporation"

[[tenants]]
name = "CNTO"
tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
client_id = "ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj"
client_secret = "your-secret-here"
auth_type = "clientcredentials"
description = "Contoso Corp"
```

---

## TUI Dashboard (Recommended)

The TUI is the primary interface for managing tenants:

```bash
# Launch the interactive dashboard
ctl365 tui
```

**Key TUI Features:**
- Security monitoring with real-time stats
- Generate comprehensive security reports (HTML)
- CA policy management
- Baseline deployment
- Multi-tenant switching

## Conditional Access Baseline 2025

Deploy production-ready CA policies:

```bash
# List current CA policies
ctl365 ca list

# Deploy all 46 CA Baseline 2025 policies (report-only mode)
ctl365 ca deploy --baseline 2025

# Deploy specific category
ctl365 ca deploy --baseline 2025 --category CAD  # Device policies

# Enable policies after testing
ctl365 ca enable --all-report-only  # Enable all report-only policies
ctl365 ca enable --name "CAD*"       # Enable by name pattern
```

**Categories:**
- **CAD** - Device Trust (6 policies)
- **CAL** - Legacy/Block (5 policies)
- **CAP** - Platform Protection (8 policies)
- **CAR** - Risk-Based (8 policies)
- **CAS** - Session Controls (10 policies)
- **CAU** - User Protection (9 policies)

---

## Troubleshooting

### Token Expired Error

If you see "Token expired", simply login again:

```bash
ctl365 login ACME
```

### Permission Errors

Make sure you've granted admin consent for all required Graph API permissions in Azure AD.

### Can't Find Tenant

```bash
# List all tenants
ctl365 tenant list

# Add if missing
ctl365 tenant add ACME --tenant-id ... --client-id ...
```

---

## Getting Help

```bash
# General help
ctl365 --help

# Command-specific help
ctl365 login --help
ctl365 tenant --help
ctl365 tenant add --help
```

---

## All Available Commands

```
ctl365 login       - Authenticate to Microsoft Graph API
ctl365 logout      - Clear cached credentials
ctl365 tenant      - Manage tenant configurations
ctl365 baseline    - Manage baseline configurations
ctl365 ca          - Conditional Access policy management
ctl365 export      - Export/Import for MSP operations
ctl365 audit       - Audit compliance and detect drift
ctl365 app         - Deploy and manage applications
ctl365 autopilot   - Windows Autopilot deployment
ctl365 package     - Package apps for Intune (Win32)
ctl365 script      - Deploy platform scripts
ctl365 gpo         - GPO to Intune migration
ctl365 scuba       - CISA SCuBA baseline assessment
ctl365 aadconnect  - Azure AD Connect migration
ctl365 sharepoint  - SharePoint management
ctl365 viva        - Viva Engage management
ctl365 copilot     - Copilot agents and search
ctl365 tui         - Interactive TUI dashboard
```

Run `ctl365 <command> --help` for detailed options.

---

**ctl365** - Control your cloud. Define your baseline.
