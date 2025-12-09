# 🚀 Getting Started with ctl365

**Welcome!** This guide will get you from zero to authenticated in **10 minutes**.

---

## 📋 What You'll Need

1. ✅ **Global Administrator** or **Application Administrator** access to your M365 tenant
2. ✅ **5 minutes** to set up an Azure AD app registration
3. ✅ **ctl365 binary** (built from source or downloaded)

---

## Step 1: Set Up Azure AD App Registration

**⏱️ Time: 5 minutes**

Follow our detailed guide: **[docs/APP_REGISTRATION.md](docs/APP_REGISTRATION.md)**

**Quick Summary:**
1. Go to https://portal.azure.com
2. Navigate to **Azure AD** → **App registrations** → **New registration**
3. Name it: `ctl365-automation`
4. Copy these values:
   - **Application (client) ID**
   - **Directory (tenant) ID**
5. Add **API Permissions** (Microsoft Graph → Delegated):
   - `DeviceManagementConfiguration.ReadWrite.All`
   - `DeviceManagementApps.ReadWrite.All`
   - `Directory.ReadWrite.All`
   - `Policy.ReadWrite.ConditionalAccess`
6. Click **Grant admin consent**

**✅ Done!** You now have the credentials you need.

---

## Step 2: Quick Setup & Authentication

**⏱️ Time: 2 minutes**

### Option A: Quick Login (Recommended for First-Time Users)

This is the **fastest way** to get started:

```bash
cd /data/lab/ctl365

# One command login - ctl365 will save the tenant config automatically
./target/x86_64-unknown-linux-gnu/release/ctl365 login \
  --tenant-id "YOUR-TENANT-ID-HERE" \
  --client-id "YOUR-CLIENT-ID-HERE"
```

**What happens:**
```
→ Quick setup mode: Creating tenant configuration...

→ Auto-generated tenant name: abc123def
💡 You can rename it later with: ctl365 tenant add <new-name> ...
🔐 Using device code flow (interactive mode)
✓ Tenant 'abc123def' configuration saved to ~/.config/ctl365/tenants.toml

🔐 Starting device code authentication for tenant 'abc123def'...

📱 Please visit: https://microsoft.com/devicelogin
🔑 Enter code: ABC12-DEFG3

✅ Authentication successful!
💾 Token saved to: /home/chris/.config/ctl365/cache/abc123def.token

→ Active tenant: abc123def
```

**That's it!** You're authenticated and ready to use ctl365.

---

### Option B: Pre-Configure Tenant (Better for Multi-Tenant)

If you want more control over the tenant name:

```bash
# Step 1: Add tenant with a friendly name
./target/x86_64-unknown-linux-gnu/release/ctl365 tenant add my-production-tenant \
  --tenant-id "YOUR-TENANT-ID" \
  --client-id "YOUR-CLIENT-ID" \
  --description "Production M365 Tenant"

# Step 2: Login
./target/x86_64-unknown-linux-gnu/release/ctl365 login --tenant my-production-tenant
```

---

## Step 3: Verify It Worked

```bash
# List your tenants
./target/x86_64-unknown-linux-gnu/release/ctl365 tenant list --verbose
```

**Expected output:**
```
Configured Tenants:
────────────────────────────────────────────────────────────

● my-production-tenant
  Tenant ID:    00000000-0000-0000-0000-000000000000
  Client ID:    11111111-1111-1111-1111-111111111111
  Auth Type:    DeviceCode
  Description:  Production M365 Tenant
  Status:       Authenticated (expires: 2025-11-07 20:30:00 UTC)

────────────────────────────────────────────────────────────
→ 1 tenant(s) total
→ Active: my-production-tenant
```

**✅ Success!** The green checkmark (●) and "Authenticated" status mean you're ready to go.

---

## Step 4: Test Your Access (Coming in Phase 2)

Once baseline management is implemented, you'll be able to:

```bash
# Generate a Windows baseline
./target/x86_64-unknown-linux-gnu/release/ctl365 baseline new windows

# Apply it to your tenant
./target/x86_64-unknown-linux-gnu/release/ctl365 baseline apply --file baseline.json

# Export existing config
./target/x86_64-unknown-linux-gnu/release/ctl365 baseline export --path ./backup/
```

**For now**, your authentication is working and ready for Phase 2!

---

## 🎯 Quick Reference

### Authentication Commands

```bash
# Quick login (auto-creates tenant)
ctl365 login --tenant-id "..." --client-id "..."

# Login to existing tenant
ctl365 login --tenant my-tenant

# Logout
ctl365 logout

# Logout from all
ctl365 logout --all
```

### Tenant Management

```bash
# Add tenant
ctl365 tenant add <name> --tenant-id "..." --client-id "..."

# List tenants
ctl365 tenant list
ctl365 tenant list --verbose

# Switch tenant
ctl365 tenant switch <name>

# Remove tenant
ctl365 tenant remove <name>
```

---

## 🔧 Optional: Install System-Wide

If you want to run `ctl365` from anywhere (not just the project directory):

```bash
# Option 1: Copy to /usr/local/bin (requires sudo)
sudo cp target/x86_64-unknown-linux-gnu/release/ctl365 /usr/local/bin/

# Option 2: Install via cargo
cargo install --path .

# Now you can run:
ctl365 --help
ctl365 login --tenant-id "..." --client-id "..."
```

---

## 🎉 What's Next?

### For MSPs: Add Multiple Tenants

```bash
# Customer A
ctl365 tenant add customer-a \
  --tenant-id "TENANT-A-ID" \
  --client-id "APP-A-ID"

# Customer B
ctl365 tenant add customer-b \
  --tenant-id "TENANT-B-ID" \
  --client-id "APP-B-ID"

# Switch between them
ctl365 tenant switch customer-a
ctl365 tenant switch customer-b
```

---

### For Automation: Use Client Credentials

**Setup:**
1. Create a **client secret** in Azure AD app registration
2. Copy the secret value

**Usage:**
```bash
ctl365 login \
  --tenant-id "..." \
  --client-id "..." \
  --client-secret "YOUR-SECRET" \
  --client-credentials
```

**No browser required!** Perfect for CI/CD pipelines.

---

## 📚 Full Documentation

- **[App Registration Guide](docs/APP_REGISTRATION.md)** - Detailed Azure AD setup
- **[Quick Start](QUICKSTART.md)** - Full features walkthrough
- **[Authentication Testing](TEST_AUTHENTICATION.md)** - Troubleshooting
- **[Reference Analysis](REFERENCE_ANALYSIS.md)** - Baseline frameworks

---

## 🐛 Common Issues

### "Authentication failed"
- ✅ Check tenant ID and client ID are correct
- ✅ Verify permissions granted in Azure AD
- ✅ Click "Grant admin consent" button

### "Token expired"
- ✅ Just run `ctl365 login --tenant <name>` again

### "Can't find config directory"
- ✅ Run: `mkdir -p ~/.config/ctl365/cache`

See **[TEST_AUTHENTICATION.md](TEST_AUTHENTICATION.md)** for more troubleshooting.

---

## ✅ Success Checklist

- [x] Azure AD app registration created
- [x] Permissions granted & admin consent clicked
- [x] Tenant added to ctl365
- [x] Successfully authenticated via device code
- [x] Token cached (verified with `tenant list --verbose`)
- [ ] Ready for Phase 2 (baseline management)!

---

**🎉 Congratulations!** You're all set up and ready to use ctl365.

**Next Steps:**
- Wait for Phase 2 (Windows baseline generation)
- Read [REFERENCE_ANALYSIS.md](REFERENCE_ANALYSIS.md) to see what's coming
- Star the repo and share with other MSPs!

---

**Need help?** Check the [docs/](docs/) folder or open a GitHub issue.

**ctl365** — *Control your cloud. Define your baseline.* 🚀
