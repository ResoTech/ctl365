# Getting Started with ctl365

**Welcome!** This guide will get you from zero to managing your M365 tenants in **10 minutes**.

---

## What You'll Need

1. **Global Administrator** or **Application Administrator** access to your M365 tenant
2. **5 minutes** to set up an Azure AD app registration
3. **ctl365 binary** (built from source or downloaded)

---

## Step 1: Set Up Azure AD App Registration

**Time: 5 minutes**

Follow our detailed guide: **[APP_REGISTRATION.md](APP_REGISTRATION.md)**

**Quick Summary:**
1. Go to https://portal.azure.com
2. Navigate to **Entra ID** → **App registrations** → **New registration**
3. Name it: `ctl365`
4. Copy these values:
   - **Application (client) ID**
   - **Directory (tenant) ID**
5. Add **API Permissions** (Microsoft Graph → Application):
   - `DeviceManagementConfiguration.ReadWrite.All`
   - `DeviceManagementApps.ReadWrite.All`
   - `Directory.ReadWrite.All`
   - `Policy.ReadWrite.ConditionalAccess`
   - `AuditLog.Read.All` (for security monitoring)
6. Click **Grant admin consent**

**Done!** You now have the credentials you need.

---

## Step 2: Quick Setup & Authentication

**Time: 2 minutes**

### Option A: Quick Login (Recommended)

```bash
# One command login - ctl365 will save the tenant config automatically
ctl365 login \
  --tenant-id "YOUR-TENANT-ID-HERE" \
  --client-id "YOUR-CLIENT-ID-HERE"
```

**What happens:**
```
→ Quick setup mode: Creating tenant configuration...
→ Auto-generated tenant name: abc123def
✓ Tenant 'abc123def' configuration saved to ~/.config/ctl365/tenants.toml

🔐 Starting device code authentication...
📱 Please visit: https://microsoft.com/devicelogin
🔑 Enter code: ABC12-DEFG3

✅ Authentication successful!
→ Active tenant: abc123def
```

### Option B: Pre-Configure Tenant (Better for Multi-Tenant/MSPs)

Use a short 4-character client identifier:

```bash
# Step 1: Add tenant with a 4-char identifier
ctl365 tenant add PROD \
  --tenant-id "YOUR-TENANT-ID" \
  --client-id "YOUR-CLIENT-ID" \
  --description "Production M365 Tenant"

# Step 2: Login
ctl365 login PROD
```

---

## Step 3: Verify Authentication

```bash
ctl365 tenant list --detailed
```

**Expected output:**
```
Configured Tenants:
────────────────────────────────────────────────────────────

● PROD
  Tenant ID:    00000000-0000-0000-0000-000000000000
  Client ID:    11111111-1111-1111-1111-111111111111
  Auth Type:    DeviceCode
  Description:  Production M365 Tenant
  Status:       Authenticated (expires: 2025-12-07 20:30:00 UTC)

────────────────────────────────────────────────────────────
→ 1 tenant(s) total
→ Active: PROD
```

---

## Step 4: Launch the TUI Dashboard (Recommended)

The TUI is the **primary interface** for ctl365:

```bash
ctl365 tui dashboard
```

From the dashboard you can:
- **Manage Clients** - Add/switch tenants
- **Deploy Baselines** - Windows, macOS, iOS, Android
- **Conditional Access** - Deploy 44 CA policies
- **Security Monitoring** - Sign-in logs, risky users
- **Generate Reports** - HTML security reports

**Keyboard shortcuts:**
- `↑/↓` or `j/k` - Navigate menus
- `Enter` - Select item
- `b` - Go back
- `?` - Help
- `q` - Quit

---

## Step 5: Deploy Your First Baseline

### Via TUI (Recommended)
1. Launch: `ctl365 tui dashboard`
2. Select **Deploy Baseline**
3. Choose **Windows - OIB v3.6**
4. Confirm the deployment

### Via CLI
```bash
# Generate a Windows baseline with BitLocker and Defender
ctl365 baseline new windows --template oib --encryption --defender -o baseline.json

# Preview what will be deployed
ctl365 baseline apply --file baseline.json --dry-run

# Apply to your tenant
ctl365 baseline apply --file baseline.json
```

---

## Step 6: Deploy Conditional Access Policies

### Via TUI
1. Launch: `ctl365 tui dashboard`
2. Select **Conditional Access**
3. View or deploy CA Baseline 2025 (44 policies)

### Via CLI
```bash
# Deploy all 44 CA policies in report-only mode
ctl365 ca deploy --baseline 2025 --report-only

# List deployed policies
ctl365 ca list

# Enable policies after testing
ctl365 ca enable --name "CAU001*"
```

---

## Quick Reference

### Authentication
```bash
ctl365 login --tenant-id "..." --client-id "..."   # Quick setup
ctl365 login ACME                                   # Existing tenant
ctl365 logout                                       # Current tenant
ctl365 logout --all                                 # All tenants
```

### Tenant Management
```bash
ctl365 tenant add ACME --tenant-id "..." --client-id "..."
ctl365 tenant list --detailed
ctl365 tenant switch ACME
ctl365 tenant remove ACME
```

### Baselines
```bash
ctl365 baseline list                                # Show available templates
ctl365 baseline new windows --template oib          # Generate baseline
ctl365 baseline apply --file baseline.json          # Deploy
ctl365 baseline apply --file baseline.json --dry-run # Preview only
```

### Conditional Access
```bash
ctl365 ca list                                      # List CA policies
ctl365 ca deploy --baseline 2025                    # Deploy CA Baseline 2025
ctl365 ca enable --name "CAD*"                      # Enable by pattern
```

### TUI Commands
```bash
ctl365 tui dashboard      # Full dashboard (recommended)
ctl365 tui clients        # MSP client management
ctl365 tui configure      # Configure active tenant
ctl365 tui defender       # Defender for Office 365
ctl365 tui exchange       # Exchange Online
ctl365 tui sharepoint     # SharePoint/OneDrive
ctl365 tui teams          # Microsoft Teams
```

---

## Install System-Wide (Optional)

```bash
# Option 1: Copy to /usr/local/bin
sudo cp target/release/ctl365 /usr/local/bin/

# Option 2: Install via cargo
cargo install --path .

# Now run from anywhere:
ctl365 --help
```

---

## For MSPs: Multi-Tenant Setup

Use 4-character client identifiers for quick reference:

```bash
# Add multiple clients
ctl365 tenant add ACME \
  --tenant-id "ACME-TENANT-ID" \
  --client-id "ACME-APP-ID"

ctl365 tenant add CNTO \
  --tenant-id "CONTOSO-TENANT-ID" \
  --client-id "CONTOSO-APP-ID"

# Switch between them
ctl365 tenant switch ACME
ctl365 tenant switch CNTO

# Or use the TUI for visual management
ctl365 tui clients
```

---

## Client Credentials Flow (Non-Interactive)

**Setup:**
1. Create a **client secret** in your Azure AD app registration
2. Copy the secret value

**Usage:**
```bash
ctl365 tenant add AUTO \
  --tenant-id "..." \
  --client-id "..." \
  --client-secret "YOUR-SECRET" \
  --client-credentials

ctl365 login AUTO
```

**No browser required!** Perfect for CI/CD pipelines and scheduled tasks.

---

## Common Issues

### "Authentication failed"
- Check tenant ID and client ID are correct
- Verify permissions granted in Azure AD
- Click "Grant admin consent" button
- Wait 5 minutes for permissions to propagate

### "Token expired"
```bash
ctl365 login --tenant <name>
```

### "Can't find config directory"
```bash
mkdir -p ~/.config/ctl365/cache
```

### "Permission denied" errors
- Verify all Graph API permissions are granted
- Check admin consent status in Azure portal
- Some features require Entra ID P1/P2 license

---

## Success Checklist

- [x] Azure AD app registration created
- [x] Permissions granted & admin consent clicked
- [x] Tenant added to ctl365
- [x] Successfully authenticated
- [x] Token cached (verified with `tenant list --detailed`)
- [x] TUI dashboard launches (`ctl365 tui dashboard`)
- [ ] First baseline deployed
- [ ] CA policies deployed (report-only mode)

---

## Full Documentation

- **[APP_REGISTRATION.md](APP_REGISTRATION.md)** - Detailed Azure AD setup
- **[COMMANDS.md](COMMANDS.md)** - Complete command reference
- **[PERMISSIONS.md](PERMISSIONS.md)** - Required Graph API permissions
- **[QUICKSTART.md](QUICKSTART.md)** - Feature walkthrough
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues

---

**Need help?** Check the [docs/](.) folder or open a GitHub issue.

**ctl365** — *Control, configure, and secure Microsoft 365 — at scale.*
