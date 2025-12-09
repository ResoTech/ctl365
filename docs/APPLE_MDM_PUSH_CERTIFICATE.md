# Apple MDM Push Certificate Setup for macOS Management

**Required Before Deploying macOS Baselines**

## ⚠️ Important: Manual Process Required

The Apple MDM Push Certificate **CANNOT be automated** due to Apple's security requirements. This is a one-time manual setup that must be completed by a human administrator with an Apple ID.

---

## 📋 Prerequisites

- ✅ **Apple ID** (personal or corporate)
  - Recommended: Create a dedicated `mdm@yourcompany.com` Apple ID
  - This Apple ID will "own" the certificate for its lifetime
- ✅ **Global Administrator** or **Intune Administrator** role in Microsoft 365
- ✅ **Access to Entra admin center** (https://intune.microsoft.com)
- ✅ **Access to Apple Push Certificates Portal** (https://identity.apple.com/pushcert)

---

## 🔄 Step-by-Step Process

### Step 1: Download CSR from Microsoft Intune

1. Navigate to **Intune admin center**: https://intune.microsoft.com
2. Go to **Devices** → **Enrollment** → **Apple enrollment**
3. Select **Apple MDM Push certificate**
4. Click **"I agree"** to grant Microsoft permission to send device info to Apple
5. Click **"Download your CSR"** button
   - This downloads: `Microsoft Corporation_Certificate_Request.csr`
   - ⚠️ Do NOT close this page - you'll return here in Step 3

### Step 2: Create Apple MDM Push Certificate

1. Open **Apple Push Certificates Portal**: https://identity.apple.com/pushcert
2. Sign in with your **Apple ID**
   - ⚠️ **Important**: Remember this Apple ID - you'll need it every year for renewal
3. Click **"Create a Certificate"** button
4. Click **"Choose File"** and upload the CSR from Step 1:
   - `Microsoft Corporation_Certificate_Request.csr`
5. Click **"Upload"**
6. Apple generates and displays your certificate
7. Click **"Download"** to save the `.pem` file:
   - Example: `MDM_Microsoft Corporation_Certificate.pem`
8. **Keep this page open** - you may need the serial number

### Step 3: Upload Certificate to Microsoft Intune

1. Return to the **Intune admin center** tab (from Step 1)
2. In the **"Apple ID"** field, enter the Apple ID you used in Step 2
   - Example: `christopher@cktech.org`
3. Click **"Browse to your Apple MDM push certificate to upload"**
4. Select the `.pem` file from Step 2:
   - `MDM_Microsoft Corporation_Certificate.pem`
5. Click **"Upload"**
6. Verify the certificate details:
   - **Status**: Active
   - **Expiration**: 365 days from today
   - **Apple ID**: Matches what you entered

### Step 4: Verify Certificate Status

After upload, you should see:

```
Configure MDM Push Certificate
Status: Active
Last updated: 11/7/2025
Apple ID: christopher@cktech.org
Serial number: 21F9C0FA49829B2B
Days until expiration: 365
Expiration: 11/7/2026
Subject ID: com.apple.mgmt.External.20a29fdc-0b24-409d-8cef-d78a964133e2
```

✅ **Certificate is now active and macOS enrollment is enabled!**

---

## 🔒 Security Best Practices

### Use a Dedicated Apple ID

❌ **Don't use personal Apple IDs** (e.g., `john.doe@icloud.com`)
✅ **Do use a company-managed Apple ID** (e.g., `mdm@company.com`)

**Why?**
- Certificate is tied to this Apple ID forever (until it expires)
- If the person leaves the company, you need their credentials to renew
- Personal Apple IDs may have 2FA that the company can't access

### Recommended Apple ID Setup

1. Create: `mdm@yourcompany.com` (or `intune@yourcompany.com`)
2. Use a **company email alias** that multiple admins can access
3. Store credentials in **company password vault** (e.g., 1Password, Bitwarden)
4. Enable **2FA** but ensure recovery codes are stored securely
5. Document the Apple ID in your runbook

---

## 🔄 Certificate Renewal (Annual)

⚠️ **Certificates expire after 365 days**

### 30 Days Before Expiration

1. Intune will show a warning banner
2. You'll receive email notifications (if configured)

### Renewal Process

**Same process as initial setup:**
1. Go to Intune admin center → Apple MDM Push certificate
2. Download **new CSR** from Microsoft
3. Go to Apple Push Certificates Portal
4. Sign in with **the same Apple ID** you used originally
5. Click **"Renew"** (not "Create new")
6. Upload the new CSR
7. Download the renewed `.pem` file
8. Upload to Intune

⚠️ **Critical**: Must use the **same Apple ID** for renewal, or all enrolled devices will break!

---

## 🚨 What Happens if Certificate Expires?

If the certificate expires:
- ❌ **All macOS devices lose management**
- ❌ Cannot push new policies
- ❌ Cannot wipe or retire devices
- ❌ Devices won't check in to Intune
- ⚠️ **Devices remain encrypted with FileVault** (recovery keys in Intune still work)

### Recovery Steps

1. Renew the certificate immediately (follow renewal process)
2. Wait 24-48 hours for devices to check in
3. Some devices may need manual re-enrollment

---

## 📝 Documentation to Keep

### Store These Details in Your Password Vault

```
Service: Apple MDM Push Certificate
Apple ID: mdm@yourcompany.com
Password: [stored in vault]
2FA Recovery Codes: [stored separately]
Certificate Serial Number: 21F9C0FA49829B2B
Subject ID: com.apple.mgmt.External.20a29fdc-0b24-409d-8cef-d78a964133e2
Created: 11/7/2025
Expires: 11/7/2026
Renewal Date: ~10/7/2026 (30 days before expiration)
```

### Calendar Reminders

Set these reminders:
- **11/7/2026** - Certificate expires (365 days)
- **10/7/2026** - Start renewal process (30 days before)
- **9/7/2026** - Pre-renewal notice (60 days before)

---

## 🛠️ Troubleshooting

### "Apple ID not recognized"
- Verify you're using the correct Apple ID
- Try signing out and back in to Apple Push Certificates Portal
- Clear browser cache and try again

### "CSR invalid or already used"
- Download a fresh CSR from Intune (they're single-use)
- Don't reuse old CSR files

### "Certificate upload failed"
- Verify the `.pem` file is not corrupted
- Re-download from Apple and try again
- Ensure file name has no special characters

### "Wrong certificate uploaded"
- You may have downloaded the wrong cert from Apple
- Go back to Apple portal and download the correct one
- The file should be named: `MDM_Microsoft Corporation_Certificate.pem`

---

## 🔗 Related Documentation

After completing this setup, proceed with:
- **[macOS Baseline Deployment](MACOS_DEPLOYMENT.md)**
- **[Apple Business Manager Setup](APPLE_BUSINESS_MANAGER.md)** (for ADE)
- **[macOS Autopilot Configuration](MACOS_AUTOPILOT.md)**

---

## ✅ Verification Checklist

Before deploying macOS baselines, verify:

- [ ] Apple MDM Push Certificate is **Active**
- [ ] Certificate shows 365 days until expiration
- [ ] Apple ID is documented and accessible
- [ ] Calendar reminders set for renewal
- [ ] Recovery codes stored in password vault
- [ ] 2FA configured and backed up
- [ ] Certificate serial number documented

Once all items are checked, you can proceed with:

```bash
# Deploy macOS baseline to Intune
ctl365 baseline new macos --template oib --encryption --defender --output macos-baseline.json
ctl365 baseline apply --file macos-baseline.json --group-id <your-macos-devices-group>
```

---

## 📞 Support Resources

- **Apple Push Certificates Portal**: https://identity.apple.com/pushcert
- **Apple MDM Documentation**: https://support.apple.com/guide/deployment/intro-to-mdm-depc0aadd3fe
- **Microsoft Intune macOS Docs**: https://learn.microsoft.com/en-us/mem/intune/enrollment/apple-mdm-push-certificate-get
- **Intune Admin Center**: https://intune.microsoft.com

---

**⚠️ Remember**: This is a **one-time manual process** that cannot be automated due to Apple's security requirements. Plan for 15-20 minutes to complete the initial setup.
