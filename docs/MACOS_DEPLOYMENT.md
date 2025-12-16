# macOS Deployment Guide - OpenIntuneBaseline v1.0

Complete guide for deploying production-ready macOS management with Intune.

---

## 📋 Prerequisites (Complete These First!)

### 1. ✅ Apple MDM Push Certificate
**Status**: ⚠️ MANUAL REQUIREMENT
- See **[APPLE_MDM_PUSH_CERTIFICATE.md](APPLE_MDM_PUSH_CERTIFICATE.md)** for setup
- This MUST be completed before macOS devices can be managed
- Takes 15-20 minutes

### 2. ✅ Apple Business Manager (Optional but Recommended)
For automated device enrollment (ADE):
- Company must be enrolled in Apple Business Manager
- Devices purchased through Apple or authorized resellers
- Enables "zero-touch" deployment

### 3. ✅ Licensing
Devices require one of:
- M365 Business Premium
- M365 E3 + Microsoft Defender for Endpoint P1/P2
- M365 E5/A5

### 4. ✅ Supported macOS Versions
- macOS Sonoma (14.6+) - **Recommended**
- macOS Ventura (13.0+) - Supported
- Apple Silicon (M1/M2/M3) - **Recommended**
- Intel Macs - Supported (but some features limited)

---

## 🚀 Deployment Options

Choose one:

### Option A: ctl365 (Automated - Recommended)
```bash
# Generate baseline
ctl365 baseline new macos --template oib --encryption --defender --output macos-baseline.json

# Review the generated JSON
cat macos-baseline.json | jq '.policies[] | {name: (.displayName // .name)}'

# Deploy to Intune
ctl365 login --tenant-id "YOUR-TENANT-ID" --client-id "YOUR-CLIENT-ID"
ctl365 baseline apply --file macos-baseline.json --group-id <macos-devices-group-id>
```

### Option B: Manual (Intune Admin Center)
1. Navigate to https://intune.microsoft.com
2. Go to **Devices** → **Configuration profiles**
3. Create policies manually based on OIB specifications

---

## 📦 What Gets Deployed (OIB v1.0)

### Compliance Policies (3)
1. **Device Health**
   - macOS 14.6+ required
   - System Integrity Protection enabled
   - FileVault encryption (if enabled)
   - Defender for Endpoint integration (if enabled)

2. **Device Security**
   - Gatekeeper: Mac App Store + Identified Developers only
   - Firewall enabled
   - Secure Boot (Apple Silicon)

3. **Password/Authentication**
   - Managed via Entra ID + Platform SSO
   - Passwordless with Secure Enclave

### Configuration Policies (8)

4. **FileVault Disk Encryption** (if `--encryption` flag used)
   - XTS-AES 256 encryption
   - Recovery key escrow to Entra ID
   - Automatic enable at setup

5. **Gatekeeper & Firewall**
   - Block unsigned applications
   - Firewall stealth mode
   - Only allow trusted developers

6. **Device Restrictions**
   - Screen capture restrictions
   - Camera/microphone controls
   - Siri data privacy

7. **Accounts and Login**
   - Local account management
   - Screen lock timeout (5 minutes)
   - Login window settings

8. **Platform SSO (Secure Enclave)**
   - Entra ID join via biometric/PIN
   - Passwordless authentication
   - Token protection

9. **Microsoft Defender Antivirus** (if `--defender` flag used)
   - Real-time protection
   - Cloud-delivered protection
   - Automatic sample submission

10. **Defender for Endpoint EDR** (if `--defender` flag used)
    - Threat detection
    - Endpoint detection and response
    - Integration with security.microsoft.com

11. **Microsoft AutoUpdate**
    - Automatic updates for M365 Apps
    - Update channel configuration

---

## 🔧 Step-by-Step Deployment

### Step 1: Authenticate to Microsoft 365

```bash
ctl365 login \
  --tenant-id "your-tenant-id-here" \
  --client-id "your-client-id-here"
```

Or for multiple tenants (use 4-char client identifier):
```bash
ctl365 tenant add ACME \
  --tenant-id "tenant-id" \
  --client-id "client-id" \
  --description "Production macOS Management"

ctl365 login ACME
```

### Step 2: Create Entra ID Group for macOS Devices

```bash
# In Azure Portal or via Graph API
# Create group: "MDM - macOS Devices"
# Type: Security Group
# Membership: Dynamic Device
# Rule: (device.deviceOSType -eq "MacMDM")
```

Save the Group ID - you'll need it for deployment.

### Step 3: Generate macOS Baseline

#### Basic Baseline
```bash
ctl365 baseline new macos \
  --template basic \
  --output macos-basic.json
```

#### Full OIB Baseline (Recommended)
```bash
ctl365 baseline new macos \
  --template oib \
  --encryption \
  --defender \
  --name "Production" \
  --output macos-production.json
```

**Generated Policies:**
- 3 Compliance policies
- 8 Configuration policies
- Total: 11 policies

### Step 4: Review Generated Baseline

```bash
# View policy summary
cat macos-production.json | jq '{
  template: .template,
  platform: .platform,
  total_policies: (.policies | length),
  policies: [.policies[] | {
    name: (.displayName // .name),
    type: .["@odata.type"]
  }]
}'

# Check metadata
cat macos-production.json | jq '.metadata'
```

### Step 5: Deploy to Intune

```bash
ctl365 baseline apply \
  --file macos-production.json \
  --group-id "your-macos-group-id-here"
```

**Dry Run First (Recommended):**
```bash
ctl365 baseline apply \
  --file macos-production.json \
  --group-id "your-macos-group-id-here" \
  --dry-run
```

### Step 6: Verify Deployment

```bash
# Check Intune admin center
# Navigate to: Devices → Configuration profiles
# Verify all 11 policies show "Assigned"
```

---

## 🍎 Enrolling macOS Devices

### Method 1: Apple Business Manager + ADE (Recommended)

**User Experience:**
1. Unbox new Mac
2. Power on
3. Setup Assistant → Connect to WiFi
4. Prompt to sign in with Entra ID
5. Automated enrollment begins
6. FileVault enabled automatically
7. Policies applied within 15-30 minutes

**Setup Required:**
- Devices assigned to Intune in Apple Business Manager
- ADE profile configured in Intune
- "Await Final Configuration" enabled
- "Locked Enrollment" enabled

### Method 2: Company Portal (User-Initiated)

**User Experience:**
1. Mac already in use (personal or existing)
2. Download **Company Portal** from Mac App Store
3. Sign in with Entra ID credentials
4. Click **"Enroll Device"**
5. Follow prompts to install management profile
6. Restart Mac
7. Policies apply within 30-60 minutes

**Limitations:**
- FileVault cannot be enforced on existing encrypted Macs
- Some profiles require wipe/reset to fully apply
- Best for BYOD scenarios

---

## 🔍 Post-Deployment Verification

### Check Policy Status (Intune Portal)

1. Navigate to https://intune.microsoft.com
2. Go to **Devices** → **macOS** → **Device compliance**
3. Verify devices show **"Compliant"**
4. Check **Configuration profiles** → Assignment status

### Check on Mac Device

```bash
# Verify MDM enrollment
sudo profiles show -type enrollment

# Check installed profiles
sudo profiles list

# Verify FileVault status
fdesetup status

# Check Gatekeeper
spctl --status

# Verify Defender is running (if deployed)
sudo mdatp health
```

---

## 🎯 Compliance Policy Actions

Devices that don't meet compliance:
- **Grace Period**: 6 hours
- **Action**: Block access to company resources
- **Email Notification**: User receives instructions

### User Remediation Steps

If device shows "Not Compliant":
1. Open **Company Portal** app
2. View compliance issues
3. Click **"Resolve"** for each issue
4. Examples:
   - Update macOS to 14.6+
   - Enable FileVault
   - Install Defender for Endpoint
   - Enable Firewall

---

## 🔐 Security Features

### FileVault Encryption
- **Algorithm**: XTS-AES 256
- **Recovery Key**: Escrowed to Entra ID
- **User Impact**: Transparent after initial setup
- **IT Recovery**: Available in Intune admin center

### Platform SSO (Passwordless)
- **Authentication**: Face ID / Touch ID / PIN
- **Token**: Stored in Secure Enclave (hardware)
- **Offline**: Works without network for 24 hours
- **MFA**: Integrated with Entra ID Conditional Access

### Defender for Endpoint
- **Real-time Protection**: Blocks malware on access
- **Cloud Intelligence**: Microsoft threat intelligence
- **EDR**: Behavioral analysis and threat hunting
- **Portal**: security.microsoft.com

---

## 🚨 Troubleshooting

### Device Won't Enroll

**Check:**
1. Apple MDM Push Certificate is active (Intune admin center)
2. User has Intune license assigned
3. Device is running supported macOS version (14.6+)
4. Internet connectivity to Apple and Microsoft servers

**Required URLs** (whitelist these):
- `*.apple.com`
- `*.icloud.com`
- `*.microsoft.com`
- `*.windows.net`

### FileVault Not Enabling

**Causes:**
- Device already encrypted with personal key
- User doesn't have admin rights
- Policy not assigned to device group

**Solution:**
- Wipe device and re-enroll (for corporate devices)
- Or use Company Portal to manually enable

### Defender Not Installing

**Causes:**
- Missing Microsoft Defender for Endpoint license
- Full Disk Access not granted
- System Extension blocked

**Solution:**
1. Go to **System Settings** → **Privacy & Security**
2. Allow **Microsoft Defender** extensions
3. Restart Mac

### Policies Show "Pending"

**Wait Time**: Up to 8 hours for initial check-in
**Force Sync**: Open Company Portal → Click sync icon

---

## 📊 Monitoring & Reporting

### Intune Admin Center Dashboards

1. **Device Compliance**
   - Devices → macOS → Compliance policies
   - View compliance status per policy

2. **Configuration Status**
   - Devices → Configuration profiles
   - Check assignment success rate

3. **Defender for Endpoint**
   - https://security.microsoft.com
   - Devices → Device inventory
   - View threat detections

### Key Metrics to Monitor

- **Compliance Rate**: Target 95%+
- **Policy Success Rate**: Target 98%+
- **Enrollment Success**: Target 90%+ (first 24 hours)
- **Defender Onboarding**: Target 100% (enrolled devices)

---

## 🔄 Updating the Baseline

When you need to modify policies:

```bash
# Generate updated baseline
ctl365 baseline new macos --template oib --encryption --defender --output macos-v2.json

# Review changes
diff <(jq -S . macos-production.json) <(jq -S . macos-v2.json)

# Apply updates (will update existing policies)
ctl365 baseline apply --file macos-v2.json --group-id <group-id>
```

---

## 🎓 User Training Materials

Provide users with:
- **Welcome Email**: Explain why device management is required
- **Enrollment Guide**: Step-by-step with screenshots
- **FAQ**: Common questions about privacy, monitoring
- **Support Contact**: IT help desk info

Sample topics:
- "What is Intune and why do I need it?"
- "Will IT see my personal files?" (No - only device settings)
- "Can I use my Mac for personal use?" (Yes, if BYOD allowed)
- "How do I get help with enrollment issues?"

---

## ✅ Deployment Checklist

- [ ] Apple MDM Push Certificate configured and active
- [ ] Apple Business Manager setup (if using ADE)
- [ ] Entra ID group created for macOS devices
- [ ] Baseline generated and reviewed
- [ ] Test deployment to pilot group (5-10 devices)
- [ ] Pilot users trained and supported
- [ ] Pilot feedback collected and issues resolved
- [ ] Full deployment to production group
- [ ] Post-deployment verification completed
- [ ] Monitoring dashboards configured
- [ ] User training materials distributed
- [ ] IT support team trained on troubleshooting

---

**Ready to deploy?**

```bash
ctl365 baseline new macos --template oib --encryption --defender --output macos.json
ctl365 baseline apply --file macos.json --group-id <your-group-id>
```

🎉 **Your macOS fleet is now enterprise-managed!**
