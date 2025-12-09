# 🚀 Quick Start Guide - ctl365

## Phase 1 Complete: Authentication & Multi-Tenant Management ✅

The foundation is now ready! Here's what's working:

### ✅ Features Available Now

- **Microsoft Graph Authentication**
  - Device code flow (interactive)
  - Client credentials flow (automation)
  - Secure token caching in `~/.ctl365/`

- **Multi-Tenant Management**
  - Add/list/switch/remove tenants
  - Per-tenant authentication
  - Easy tenant switching

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

#### Option A: Interactive Login (Device Code Flow)

```bash
ctl365 tenant add my-tenant \
  --tenant-id "00000000-0000-0000-0000-000000000000" \
  --client-id "11111111-1111-1111-1111-111111111111"
```

#### Option B: Automation (Client Credentials Flow)

```bash
ctl365 tenant add my-tenant \
  --tenant-id "00000000-0000-0000-0000-000000000000" \
  --client-id "11111111-1111-1111-1111-111111111111" \
  --client-secret "your-client-secret" \
  --client-credentials
```

### 2. Login to Microsoft Graph

```bash
# Login to the tenant you just added
ctl365 login --tenant my-tenant
```

This will:
1. Open a browser prompt (device code flow)
2. Ask you to visit https://microsoft.com/devicelogin
3. Enter the code displayed
4. Save your access token securely to `~/.ctl365/cache/my-tenant.token`

### 3. Manage Multiple Tenants

```bash
# List all configured tenants
ctl365 tenant list

# List with detailed info (shows auth status)
ctl365 tenant list --verbose

# Add another tenant
ctl365 tenant add contoso \
  --tenant-id "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" \
  --client-id "ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj"

# Switch active tenant
ctl365 tenant switch contoso

# Login to the new tenant
ctl365 login --tenant contoso
```

### 4. Logout

```bash
# Logout from current tenant
ctl365 logout

# Logout from specific tenant
ctl365 logout --tenant my-tenant

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
4. Name: `ctl365-automation` (or your preference)
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

#### For Client Credentials Flow (Automation):
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
    └── my-tenant.token  # Cached access tokens (per tenant)
```

### Example `tenants.toml`:

```toml
[[tenants]]
name = "my-tenant"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "11111111-1111-1111-1111-111111111111"
auth_type = "devicecode"
description = "Production tenant"

[[tenants]]
name = "contoso"
tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
client_id = "ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj"
client_secret = "your-secret-here"
auth_type = "clientcredentials"
description = "MSP customer - Contoso Corp"
```

---

## Next Steps (Coming Soon)

Phase 2 will add:
- ✅ Windows 11 25H2 baseline generation
- ✅ BitLocker enforcement
- ✅ Defender ATP onboarding
- ✅ Baseline apply/export commands

Stay tuned!

---

## Troubleshooting

### Token Expired Error

If you see "Token expired", simply login again:

```bash
ctl365 login --tenant my-tenant
```

### Permission Errors

Make sure you've granted admin consent for all required Graph API permissions in Azure AD.

### Can't Find Tenant

```bash
# List all tenants
ctl365 tenant list

# Add if missing
ctl365 tenant add my-tenant --tenant-id ... --client-id ...
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

**ctl365** — *Control your cloud. Define your baseline.*
