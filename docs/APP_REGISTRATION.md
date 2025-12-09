# 🔐 Azure AD App Registration Setup for ctl365

This guide walks you through creating an Azure AD app registration to authenticate **ctl365** with your Microsoft 365 tenant.

---

## 📋 Overview

**ctl365** needs an Azure AD app registration to access Microsoft Graph APIs. This is the **recommended authentication method** and gives you full control over permissions and security.

**Time Required:** ~10 minutes
**Prerequisites:** Global Administrator or Application Administrator role

---

## 🎯 What You'll Get

By the end of this guide, you'll have:
- ✅ An Azure AD app registration for ctl365
- ✅ Application (Client) ID
- ✅ Directory (Tenant) ID
- ✅ Proper Microsoft Graph API permissions
- ✅ Admin consent granted
- ✅ (Optional) Client secret for automation

---

## 🚀 Step-by-Step Setup

### Step 1: Navigate to Azure AD

1. Open a browser and go to: https://portal.azure.com
2. Sign in with your **Global Administrator** or **Application Administrator** account
3. In the search bar at the top, type: `Azure Active Directory`
4. Click **Azure Active Directory** from the results

**Alternative Path:**
- Navigate to: **Azure Active Directory** → **App registrations** (left sidebar)

---

### Step 2: Create New App Registration

1. In the **App registrations** blade, click **+ New registration** (top left)

2. **Fill in the registration form:**

   **Name:**
   ```
   ctl365-automation
   ```
   *You can use any name, but this helps identify it later*

   **Supported account types:**
   - ✅ Select: **Accounts in this organizational directory only (Single tenant)**

   *This is the most secure option for internal tools*

   **Redirect URI (optional):**
   - Leave this **blank** for now
   - *(Device code flow doesn't need redirect URIs)*

3. Click **Register** (bottom left)

---

### Step 3: Copy Your Credentials

After registration, you'll see the **Overview** page.

**📝 COPY THESE VALUES** (you'll need them for ctl365):

```
Application (client) ID:  ________________________________
Directory (tenant) ID:    ________________________________
```

**How to find them:**
- **Application (client) ID**: Visible on the Overview page under "Essentials"
- **Directory (tenant) ID**: Also on the Overview page under "Essentials"

**💾 Save these somewhere safe** (password manager, secure note, etc.)

---

### Step 4: Configure API Permissions

Now we'll grant ctl365 access to Microsoft Graph APIs.

1. In the left sidebar, click **API permissions**

2. Click **+ Add a permission**

3. Click **Microsoft Graph**

4. Choose **Delegated permissions** (for interactive login)

5. **Add the following permissions:**

   Search and check each one:

   **Device Management:**
   ```
   ☑ DeviceManagementConfiguration.ReadWrite.All
   ☑ DeviceManagementApps.ReadWrite.All
   ☑ DeviceManagementManagedDevices.ReadWrite.All
   ```

   **Directory & Groups:**
   ```
   ☑ Directory.ReadWrite.All
   ☑ Group.ReadWrite.All
   ```

   **Conditional Access:**
   ```
   ☑ Policy.ReadWrite.ConditionalAccess
   ```

   **Exchange & Security (Optional but recommended):**
   ```
   ☑ Exchange.ManageAsApp (Application permission)
   ☑ SecurityEvents.Read.All
   ```

6. Click **Add permissions** (bottom)

---

### Step 5: Grant Admin Consent

This is **critical** - without this, users will see consent prompts.

1. Still on the **API permissions** page
2. Click **Grant admin consent for [Your Organization Name]**
3. Click **Yes** on the confirmation dialog
4. Wait for the green checkmarks to appear in the "Status" column

**Expected Result:**
```
Permission                                     Type        Status
DeviceManagementConfiguration.ReadWrite.All   Delegated   ✓ Granted for [Org]
DeviceManagementApps.ReadWrite.All           Delegated   ✓ Granted for [Org]
...
```

---

### Step 6 (Optional): Create Client Secret for Automation

If you want to use **client credentials flow** (non-interactive/automation), create a client secret.

**⚠️ Skip this if you only need interactive login**

1. In the left sidebar, click **Certificates & secrets**

2. Click **+ New client secret**

3. **Fill in:**
   ```
   Description: ctl365-automation-secret
   Expires:     6 months (or your preference)
   ```

4. Click **Add**

5. **IMMEDIATELY COPY THE VALUE** - you won't see it again!
   ```
   Client Secret Value: ________________________________
   ```

**💾 Store this securely** (it's like a password!)

---

## ✅ Verification Checklist

Before proceeding, verify:

- [ ] App registration created
- [ ] Application (client) ID copied
- [ ] Directory (tenant) ID copied
- [ ] Delegated permissions added (at least Device Management permissions)
- [ ] Admin consent granted (green checkmarks visible)
- [ ] (Optional) Client secret created and copied

---

## 🔧 Using Your App Registration with ctl365

### Interactive Login (Device Code Flow)

```bash
# Add your tenant to ctl365
ctl365 tenant add my-tenant \
  --tenant-id "YOUR-TENANT-ID-HERE" \
  --client-id "YOUR-CLIENT-ID-HERE" \
  --description "Production M365 Tenant"

# Login (will prompt for browser authentication)
ctl365 login --tenant my-tenant
```

**What happens:**
1. ctl365 generates a device code
2. You visit https://microsoft.com/devicelogin
3. Enter the code and sign in
4. ctl365 receives access token
5. Token saved to `~/.ctl365/cache/my-tenant.token`

---

### Automation (Client Credentials Flow)

**⚠️ Only use if you created a client secret**

```bash
# Add tenant with client secret
ctl365 tenant add my-automation \
  --tenant-id "YOUR-TENANT-ID" \
  --client-id "YOUR-CLIENT-ID" \
  --client-secret "YOUR-CLIENT-SECRET" \
  --client-credentials

# Login (no browser required!)
ctl365 login --tenant my-automation
```

**Use cases:**
- CI/CD pipelines
- Scheduled baseline deployments
- Automated compliance checks
- Multi-tenant MSP operations

---

## 🔒 Security Best Practices

### 1. **Use Managed Identities (Future)**
For Azure-hosted runners, use Managed Identities instead of client secrets.

### 2. **Rotate Client Secrets Regularly**
If using client credentials:
- Set expiration to 6-12 months
- Set calendar reminder to rotate before expiry
- Never commit secrets to Git

### 3. **Principle of Least Privilege**
Only grant permissions you actually need:
- Testing setup? Start with `DeviceManagementConfiguration.Read.All`
- Only need compliance? Skip `Apps.ReadWrite.All`

### 4. **Monitor App Usage**
Check Azure AD sign-in logs periodically:
```
Azure AD → Sign-in logs → Filter by "Application ID"
```

### 5. **Use Certificate Authentication (Advanced)**
Instead of client secrets, use certificate-based auth:
1. Generate X.509 certificate
2. Upload public key to Azure AD app
3. Store private key securely
4. ctl365 will support this in Phase 1.5

---

## 🐛 Troubleshooting

### ❌ "AADSTS65001: The user or administrator has not consented"

**Cause:** Admin consent not granted

**Fix:**
1. Go back to **API permissions** page
2. Click **Grant admin consent for [Your Org]**
3. Try login again

---

### ❌ "AADSTS700016: Application not found in directory"

**Cause:** Wrong tenant ID or app not in that tenant

**Fix:**
```bash
# Remove and re-add tenant with correct IDs
ctl365 tenant remove my-tenant
ctl365 tenant add my-tenant --tenant-id "CORRECT-ID" --client-id "CORRECT-ID"
```

---

### ❌ "Insufficient privileges to complete the operation"

**Cause:** Missing permissions or consent not granted

**Fix:**
1. Check **API permissions** page - look for red X's
2. Ensure admin consent granted (green checkmarks)
3. Wait 5 minutes for Azure AD to propagate changes
4. Try login again

---

### ❌ Client secret expired

**Symptoms:** Client credentials login fails after working previously

**Fix:**
1. Go to **Certificates & secrets**
2. Create new client secret
3. Update ctl365 config:
```bash
ctl365 tenant add my-automation \
  --tenant-id "SAME-TENANT-ID" \
  --client-id "SAME-CLIENT-ID" \
  --client-secret "NEW-SECRET" \
  --client-credentials
```

---

## 📚 Additional Resources

### Microsoft Documentation
- [Register an application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Device code flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)

### ctl365 Documentation
- [Quickstart Guide](../QUICKSTART.md)
- [Authentication Testing](../TEST_AUTHENTICATION.md)
- [Multi-Tenant Setup](./MULTI_TENANT.md)

---

## 🎯 Next Steps

Now that your app registration is ready:

1. **Test authentication:**
   ```bash
   ctl365 login --tenant my-tenant
   ```

2. **List tenants:**
   ```bash
   ctl365 tenant list --verbose
   ```

3. **Start deploying baselines** (Phase 2):
   ```bash
   ctl365 baseline new windows --template openintune
   ```

---

## 💡 Pro Tips

### For MSPs Managing Multiple Tenants

Create **one app registration per tenant**:
```bash
# Tenant A
ctl365 tenant add customer-a \
  --tenant-id "TENANT-A-ID" \
  --client-id "APP-A-ID"

# Tenant B
ctl365 tenant add customer-b \
  --tenant-id "TENANT-B-ID" \
  --client-id "APP-B-ID"

# Switch between them
ctl365 tenant switch customer-a
ctl365 baseline apply --file prod-baseline.json

ctl365 tenant switch customer-b
ctl365 baseline apply --file prod-baseline.json
```

### For Development/Testing

Create separate app registrations:
- `ctl365-dev` - Dev tenant testing
- `ctl365-prod` - Production deployments

This isolates permissions and audit logs.

---

## 🤝 Need Help?

- **Issues**: https://github.com/yourusername/ctl365/issues
- **Discussions**: https://github.com/yourusername/ctl365/discussions
- **Security concerns**: Email security@yourcompany.com

---

**🎉 Congratulations!** Your app registration is ready. You can now authenticate ctl365 with your Microsoft 365 tenant!
