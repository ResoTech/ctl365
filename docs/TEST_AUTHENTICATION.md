# 🧪 Testing ctl365 Authentication

## Prerequisites

You need an Azure AD app registration with the following permissions:

### Required Graph API Permissions (Application/Delegated)
```
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementManagedDevices.ReadWrite.All
Directory.ReadWrite.All
Policy.ReadWrite.ConditionalAccess
```

---

## Quick Azure AD App Setup

### Option 1: Using Azure Portal (Recommended for First Test)

1. Go to https://portal.azure.com
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Name it: `ctl365-test`
5. **Supported account types**: Single tenant
6. **Redirect URI**: Leave blank (not needed for device code flow)
7. Click **Register**

**Copy these values:**
- ✅ **Application (client) ID**
- ✅ **Directory (tenant) ID**

8. Go to **API permissions** → **Add a permission** → **Microsoft Graph**
9. Choose **Delegated permissions** (for device code flow)
10. Add these permissions:
   - `DeviceManagementConfiguration.ReadWrite.All`
   - `DeviceManagementApps.ReadWrite.All`
   - `Directory.Read.All` (or ReadWrite.All)
   - `Policy.Read.ConditionalAccess` (or ReadWrite)
11. Click **Grant admin consent** (requires Global Admin)

---

## Testing Authentication

### Step 1: Add Your Tenant

```bash
./target/x86_64-unknown-linux-gnu/release/ctl365 tenant add my-test-tenant \
  --tenant-id "YOUR-TENANT-ID-HERE" \
  --client-id "YOUR-CLIENT-ID-HERE" \
  --description "Test tenant for ctl365"
```

**Expected output:**
```
✓ Tenant 'my-test-tenant' added successfully

→ Run ctl365 login --tenant my-test-tenant to authenticate
```

---

### Step 2: Login (Device Code Flow)

```bash
./target/x86_64-unknown-linux-gnu/release/ctl365 login --tenant my-test-tenant
```

**Expected output:**
```
🔐 Starting device code authentication for tenant 'my-test-tenant'...

📱 Please visit: https://microsoft.com/devicelogin
🔑 Enter code: ABC12-DEFG3

✅ Authentication successful!
💾 Token saved to: /home/chris/.config/ctl365/cache/my-test-tenant.token

→ Active tenant: my-test-tenant
```

**Action Required:**
1. Open a browser to https://microsoft.com/devicelogin
2. Enter the code shown
3. Sign in with your M365 admin account
4. Approve the permissions
5. Return to terminal (it will auto-complete)

---

### Step 3: Verify Token is Cached

```bash
ls -lh ~/.config/ctl365/cache/
```

**Expected:**
```
my-test-tenant.token
```

---

### Step 4: List Tenants

```bash
./target/x86_64-unknown-linux-gnu/release/ctl365 tenant list --verbose
```

**Expected output:**
```
Configured Tenants:
────────────────────────────────────────────────────────────

● my-test-tenant
  Tenant ID:    00000000-0000-0000-0000-000000000000
  Client ID:    11111111-1111-1111-1111-111111111111
  Auth Type:    DeviceCode
  Description:  Test tenant for ctl365
  Status:       Authenticated (expires: 2025-11-07 19:30:00 UTC)

────────────────────────────────────────────────────────────
→ 1 tenant(s) total
→ Active: my-test-tenant
```

---

### Step 5: Test Re-authentication (Token Refresh)

Wait for token to expire (typically 1 hour), then run login again:

```bash
./target/x86_64-unknown-linux-gnu/release/ctl365 login --tenant my-test-tenant
```

It should prompt for device code again (we haven't implemented refresh tokens yet - that's Phase 1.5).

---

## Troubleshooting

### ❌ "Authentication failed: Device authorization request failed"

**Cause:** Invalid tenant ID or client ID

**Fix:**
```bash
# Remove the tenant
./target/x86_64-unknown-linux-gnu/release/ctl365 tenant remove my-test-tenant

# Add it again with correct IDs
./target/x86_64-unknown-linux-gnu/release/ctl365 tenant add my-test-tenant \
  --tenant-id "CORRECT-TENANT-ID" \
  --client-id "CORRECT-CLIENT-ID"
```

---

### ❌ "AADSTS65001: The user or administrator has not consented"

**Cause:** API permissions not granted

**Fix:**
1. Go to Azure Portal → App registrations → Your app
2. Click **API permissions**
3. Click **Grant admin consent for [Your Org]**
4. Try login again

---

### ❌ "Token expired" when running commands

**Cause:** Token cached but now expired

**Fix:**
```bash
# Just login again
./target/x86_64-unknown-linux-gnu/release/ctl365 login --tenant my-test-tenant
```

---

### ❌ Can't find config directory

**Fix:**
```bash
# Create it manually
mkdir -p ~/.config/ctl365/cache
```

---

## Testing Client Credentials Flow (Advanced)

If you want to test non-interactive auth (for automation):

### 1. Create Client Secret

1. Azure Portal → Your app → **Certificates & secrets**
2. **New client secret**
3. Description: `ctl365-secret`
4. Expires: 6 months (or your preference)
5. **Copy the secret value** (you won't see it again!)

### 2. Add Tenant with Secret

```bash
# Use a short abbreviation for easy reference (e.g., RESO, ACME, CLIENT1)
ctl365 tenant add RESO \
  --tenant-id "YOUR-TENANT-ID" \
  --client-id "YOUR-CLIENT-ID" \
  --client-secret "YOUR-CLIENT-SECRET" \
  --client-credentials
```

### 3. Login (No Browser Required!)

```bash
ctl365 login RESO
```

**Expected output:**
```
🔐 Authenticating with client credentials for tenant 'RESO'...
✅ Authentication successful!

→ Active tenant: RESO
```

---

## What Happens Behind the Scenes

1. **Device Code Flow:**
   - ctl365 requests device code from Azure AD
   - You authenticate in browser
   - ctl365 polls Azure AD for access token
   - Token saved to `~/.config/ctl365/cache/{tenant}.token`

2. **Token Cache Format:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1...",
  "refresh_token": null,
  "expires_at": "2025-11-07T19:30:00Z",
  "tenant_id": "00000000-0000-0000-0000-000000000000"
}
```

3. **Config Files:**
```
~/.config/ctl365/
├── config.toml          # Current tenant, settings
├── tenants.toml         # All tenant configs
└── cache/
    └── {tenant}.token   # Cached access tokens
```

---

## Next Steps After Successful Auth

Once authentication works, you can test:

```bash
# Logout
./target/x86_64-unknown-linux-gnu/release/ctl365 logout

# Switch between tenants
./target/x86_64-unknown-linux-gnu/release/ctl365 tenant switch my-other-tenant

# Remove a tenant
./target/x86_64-unknown-linux-gnu/release/ctl365 tenant remove old-tenant
```

---

## Success Criteria ✅

- [ ] Tenant added successfully
- [ ] Device code login prompt appears
- [ ] Browser authentication completes
- [ ] Token saved to cache
- [ ] `tenant list --verbose` shows "Authenticated" status
- [ ] Token persists after closing terminal
- [ ] Can logout and login again

---

Let me know what happens! 🚀
