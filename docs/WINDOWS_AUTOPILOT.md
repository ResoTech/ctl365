# Windows Autopilot Baseline Deployment

Complete guide for deploying Windows Autopilot with BitLocker, Defender Firewall, and Windows Update policies using ctl365.

---

## Overview

The Windows Autopilot baseline template provides a complete zero-touch deployment setup for Windows devices, including:

- **Dynamic Security Group** - Automatically includes company-owned Windows 11 devices
- **Autopilot Deployment Profile** - User-driven, Microsoft Entra joined
- **BitLocker Disk Encryption** - Full OS drive encryption via Endpoint Security
- **Windows Defender Firewall** - All network profiles enabled with secure defaults
- **Windows Update Ring** - Automated updates with deadlines
- **Feature Update Profile** - Deploy Windows 11 24H2/25H2

---

## Quick Start

### Generate Autopilot Baseline

```bash
# Basic autopilot baseline with defaults
ctl365 baseline new windows --template autopilot --name "Baseline"

# Custom naming (recommended for MSPs)
ctl365 baseline new windows --template autopilot --name RESO \
  --bitlocker-policy-name "RESO BitLocker" \
  --firewall-policy-name "RESO Defender Firewall" \
  --update-ring-name "RESO Ring1"

# Save to file
ctl365 baseline new windows --template autopilot --name RESO \
  --output autopilot-baseline.json
```

### Apply Baseline to Tenant

```bash
# Preview what will be created
ctl365 baseline apply --file autopilot-baseline.json --dry-run

# Apply to tenant
ctl365 baseline apply --file autopilot-baseline.json
```

---

## What Gets Created

### 1. Dynamic Security Group

**Name:** `Windows Autopilot` (customizable via `--autopilot-group-name`)

**Membership Rule:**
```
(device.deviceOSType -eq "Windows") and
(device.deviceOSVersion -startsWith "10.0.2") and
(device.deviceOwnership -eq "Company")
```

**Purpose:** Automatically includes all company-owned Windows 11 devices. The `10.0.2` prefix covers Windows 11 versions (10.0.22000+, 10.0.26100+).

**Intune Location:** Entra ID > Groups > Windows Autopilot

---

### 2. Autopilot Deployment Profile

**Name:** `{prefix} - Autopilot User-Driven`

**Configuration:**

| Setting | Value |
|---------|-------|
| Deployment mode | User-driven |
| Join type | Microsoft Entra joined (NOT hybrid) |
| Device name template | `%SERIAL%` |
| Language | en-US |
| White glove (pre-provisioning) | Disabled |

**OOBE Settings:**

| Setting | Value |
|---------|-------|
| Hide privacy settings | Yes |
| Hide EULA | Yes |
| User type | Standard |
| Device usage | Single user |
| Skip keyboard selection | Yes |
| Hide escape link | Yes |

**Enrollment Status Page:**

| Setting | Value |
|---------|-------|
| Show installation progress | Yes |
| Allow device use before complete | No |
| Block setup retry | No |
| Allow log collection on failure | Yes |
| Timeout | 60 minutes |
| Allow use on failure | Yes |

**Intune Location:** Devices > Enrollment > Windows Autopilot deployment profiles

---

### 3. BitLocker Disk Encryption

**Name:** Customizable via `--bitlocker-policy-name` (e.g., "RESO BitLocker")

**Configuration:**

| Setting | Value |
|---------|-------|
| Require device encryption | Yes |
| Allow standard user encryption | Yes (for Autopilot) |
| Recovery password rotation | Enabled for Entra joined |
| OS drive encryption | XTS-AES 256-bit |
| Encryption mode | Full disk (not used space only) |
| TPM requirement | Required |
| Recovery key backup | Azure AD |
| Removable drive encryption | Required for write access |

**Intune Location:** Endpoint Security > Disk encryption

---

### 4. Windows Defender Firewall

**Name:** Customizable via `--firewall-policy-name` (e.g., "RESO Defender Firewall")

**Configuration:**

| Profile | Firewall | Inbound Default | Outbound Default |
|---------|----------|-----------------|------------------|
| Domain | Enabled | Block | Allow |
| Private | Enabled | Block | Allow |
| Public | Enabled | Block | Allow |

**Use Cases:**
- **Domain profile:** Corporate network (domain-joined devices)
- **Private profile:** Smaller environments, home offices
- **Public profile:** Untrusted networks (coffee shops, airports)

**Intune Location:** Endpoint Security > Firewall

---

### 5. Windows Update Ring

**Name:** `{prefix} - {ring_name}` (default: "Baseline - Ring1")

**Update Settings:**

| Setting | Value |
|---------|-------|
| Microsoft product updates | Allow |
| Windows drivers | Allow |
| Quality update deferral | 0 days |
| Feature update deferral | 0 days |
| Servicing channel | General Availability |
| Upgrade Win10 to Win11 | Yes |
| Feature update uninstall period | 10 days |

**User Experience Settings:**

| Setting | Value |
|---------|-------|
| Automatic update behavior | Auto install at maintenance time |
| Active hours start | 8:00 AM |
| Active hours end | 5:00 PM |
| Option to pause updates | Disabled |
| Option to check for updates | Enabled |
| Notification level | Default Windows notifications |

**Deadline Settings:**

| Setting | Value |
|---------|-------|
| Feature update deadline | 10 days |
| Quality update deadline | 7 days |
| Grace period | 7 days |
| Auto reboot before deadline | Yes |

**Intune Location:** Devices > Windows > Update rings for Windows 10 and later

---

### 6. Feature Update Profile

**Name:** `{prefix} - Feature Update 24H2`

**Configuration:**

| Setting | Value |
|---------|-------|
| Target version | Windows 11, version 24H2 |
| Rollout start | Immediate |

**Intune Location:** Devices > Windows > Feature updates for Windows 10 and later

---

## CLI Options

### Template Selection

```bash
ctl365 baseline new windows --template autopilot
```

### Naming Options

| Option | Description | Default |
|--------|-------------|---------|
| `--name` | Prefix for all policy names | "Baseline" |
| `--autopilot-group-name` | Dynamic security group name | "Windows Autopilot" |
| `--bitlocker-policy-name` | BitLocker policy name | "{prefix} BitLocker" |
| `--firewall-policy-name` | Firewall policy name | "{prefix} Defender Firewall" |
| `--update-ring-name` | Update ring name | "Ring1" |
| `--feature-update-version` | Target Windows version | "Windows 11, version 24H2" |

### Skip Policies

| Option | Description |
|--------|-------------|
| `--no-bitlocker` | Skip BitLocker disk encryption policy |
| `--no-firewall` | Skip Windows Defender Firewall policy |
| `--no-updates` | Skip Windows Update Ring and Feature Update |

### Examples

```bash
# Full baseline with custom names
ctl365 baseline new windows --template autopilot \
  --name "Contoso" \
  --bitlocker-policy-name "Contoso BitLocker" \
  --firewall-policy-name "Contoso Firewall" \
  --update-ring-name "Production Ring"

# Autopilot + BitLocker only (no updates)
ctl365 baseline new windows --template autopilot \
  --name "Baseline" \
  --no-updates

# Autopilot profile only (minimal)
ctl365 baseline new windows --template autopilot \
  --name "Baseline" \
  --no-bitlocker \
  --no-firewall \
  --no-updates
```

---

## Prerequisites

### Licenses Required

| Feature | License |
|---------|---------|
| Windows Autopilot | Intune (M365 E3/E5, EMS E3/E5) |
| BitLocker management | Intune |
| Windows Update for Business | Intune |
| Feature updates | Windows 11 Pro/Enterprise |

### Permissions Required

For the service principal or user applying the baseline:

- **DeviceManagementConfiguration.ReadWrite.All** - Create policies
- **Group.ReadWrite.All** - Create dynamic security groups
- **DeviceManagementManagedDevices.ReadWrite.All** - Autopilot profiles

### Hardware Requirements

For BitLocker:
- TPM 2.0 (required)
- UEFI firmware
- Secure Boot enabled

For Autopilot:
- Internet connectivity during OOBE
- Hardware hash registered in Intune

---

## Deployment Workflow

### Step 1: Register Device Hardware Hashes

ctl365 supports multiple methods for importing Autopilot device hashes:

#### Method A: PowerShell Export (Single Device)

Run on the device to export its hardware hash:

```powershell
# Install the script
Install-Script -Name Get-WindowsAutopilotInfo

# Export to CSV
Get-WindowsAutopilotInfo -OutputFile C:\HWID.csv
```

Then import:

```bash
ctl365 autopilot import --file HWID.csv
```

#### Method B: OEM Bulk Import (Dell/Lenovo/HP)

Enterprise customers can get device hashes directly from OEM partners.

**Dell TechDirect:**
1. Log into [Dell TechDirect](https://techdirect.dell.com)
2. Navigate to Windows Autopilot Services
3. Export device list as CSV
4. Import with ctl365:

```bash
# Dell TechDirect export format is auto-detected
ctl365 autopilot import --file dell-devices.csv

# With group tag
ctl365 autopilot import --file dell-devices.csv --group-tag "Dell-Laptops"
```

**Lenovo:**
1. Request device hashes from your Lenovo account team
2. Or use Lenovo Device Intelligence portal
3. Export includes manufacturer info:

```bash
# Lenovo export format is auto-detected
ctl365 autopilot import --file lenovo-devices.csv
```

**HP:**
1. Use HP Device as a Service portal
2. Or request from HP partner account
3. Import:

```bash
ctl365 autopilot import --file hp-devices.csv
```

#### Method C: Partner Center Format

For CSP partners with Microsoft Partner Center access:

```bash
# Partner Center format includes manufacturer and model
ctl365 autopilot import --file partner-devices.csv
```

#### CSV Format Reference

ctl365 auto-detects the CSV format based on headers:

**Microsoft Standard Format** (from Get-WindowsAutopilotInfo):
```csv
Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User
ABC123,,AQEA9E2mxw...,Sales-Team,john@contoso.com
```

**OEM Partner Format** (Dell/Lenovo/HP):
```csv
Device Serial Number,Windows Product ID,Hardware Hash,Manufacturer name,Device model
ABC123,,AQEA9E2mxw...,Dell Inc.,Latitude 5540
DEF456,,,LENOVO,ThinkPad T14
```

#### Import Options

| Option | Description |
|--------|-------------|
| `--file` | Path to CSV file (required) |
| `--group-tag` | Apply group tag to all devices |
| `--profile-id` | Auto-assign to deployment profile |
| `--manufacturer` | Override manufacturer for all devices |
| `--model` | Override model for all devices |
| `--dry-run` | Preview import without changes |
| `-y, --yes` | Skip confirmation prompt |

#### Examples

```bash
# Dry run to preview import
ctl365 autopilot import --file devices.csv --dry-run

# Import with group tag for filtering
ctl365 autopilot import --file dell-laptops.csv --group-tag "Executive-Devices"

# Import and assign to profile
ctl365 autopilot import --file devices.csv --profile-id "abc-123-def"

# Override manufacturer for standard CSV
ctl365 autopilot import --file devices.csv --manufacturer "Dell Inc." --model "Latitude 5540"
```

#### Verify Import

```bash
# List all Autopilot devices
ctl365 autopilot list

# Filter by group tag
ctl365 autopilot list --group-tag "Dell-Laptops"

# Sync with Intune
ctl365 autopilot sync
```

### Step 2: Generate Baseline

```bash
ctl365 baseline new windows --template autopilot \
  --name "Production" \
  --output production-autopilot.json
```

### Step 3: Review Configuration

Open `production-autopilot.json` and verify:
- Policy names match your naming convention
- Settings align with your requirements
- Group membership rule is correct

### Step 4: Apply to Tenant

```bash
# Dry run first
ctl365 baseline apply --file production-autopilot.json --dry-run

# Apply
ctl365 baseline apply --file production-autopilot.json -y
```

### Step 5: Verify in Intune

1. **Entra ID** > **Groups**: Verify "Windows Autopilot" group created
2. **Devices** > **Enrollment** > **Windows Autopilot**: Verify profile
3. **Endpoint Security** > **Disk encryption**: Verify BitLocker policy
4. **Endpoint Security** > **Firewall**: Verify Firewall policy
5. **Devices** > **Windows** > **Update rings**: Verify update ring

### Step 6: Test with Pilot Device

1. Reset a test device or use new hardware
2. Connect to internet during OOBE
3. Verify Autopilot profile applies
4. Check BitLocker encryption status
5. Verify Windows Update settings

---

## Verification

### Check Dynamic Group Membership

```bash
# Via Microsoft Graph
ctl365 graph get "groups?\$filter=displayName eq 'Windows Autopilot'"
```

### Check BitLocker Status on Device

```powershell
# On the device
manage-bde -status C:
```

Expected output:
```
Conversion Status:    Fully Encrypted
Percentage Encrypted: 100%
Encryption Method:    XTS-AES 256
```

### Check Firewall Status

```powershell
# On the device
Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

Expected output:
```
Name    Enabled DefaultInboundAction DefaultOutboundAction
----    ------- -------------------- ---------------------
Domain     True                Block                 Allow
Private    True                Block                 Allow
Public     True                Block                 Allow
```

---

## Troubleshooting

### Autopilot Profile Not Applying

**Symptoms:** Device goes through standard OOBE instead of Autopilot

**Causes:**
- Hardware hash not registered
- Device not in dynamic group
- Autopilot profile not assigned

**Solution:**
```bash
# Verify device is registered
ctl365 autopilot list

# Re-sync Autopilot
ctl365 autopilot sync
```

### BitLocker Not Encrypting

**Symptoms:** Drive shows "Encryption Pending" or not encrypted

**Causes:**
- TPM not present or not ready
- Policy conflict
- User not logged in (encryption starts after login)

**Solution:**
```powershell
# Check TPM status
Get-Tpm

# Manually trigger encryption
manage-bde -on C: -RecoveryPassword
```

### Dynamic Group Empty

**Symptoms:** No devices in Windows Autopilot group

**Causes:**
- Devices not company-owned
- Devices running Windows 10 (not 11)
- Membership rule processing delay (up to 24 hours)

**Solution:**
1. Verify device ownership in Intune
2. Check Windows version (`winver`)
3. Wait for dynamic membership processing

---

## Customization

### Change Autopilot to Self-Deploying Mode

For kiosk or shared devices, modify the generated JSON:

```json
{
  "deploymentMode": "selfDeploying",
  "outOfBoxExperienceSettings": {
    "userType": "deviceOwner",
    "deviceUsageType": "shared"
  }
}
```

### Add Hybrid Azure AD Join

If you need hybrid join instead of pure Entra join, use the existing `autopilot profile` command:

```bash
ctl365 autopilot profile \
  --name "Hybrid Autopilot" \
  --mode user-driven \
  --hybrid-join
```

### Multiple Update Rings

Generate separate baselines for different rings:

```bash
# Ring 0 - IT/Pilot (immediate updates)
ctl365 baseline new windows --template autopilot \
  --name "Ring0-Pilot" \
  --update-ring-name "Ring0" \
  --no-bitlocker --no-firewall

# Ring 1 - Early adopters (7 day deferral)
# Manually edit the JSON to set deferral periods
```

---

## Related Documentation

- [Autopilot Device Import](./COMMANDS.md#autopilot)
- [Windows Baseline Templates](./COMMANDS.md#baseline-management)
- [Tenant Configuration](./TENANT_BASELINE.md)

---

## Quick Reference

```bash
# Generate full Autopilot baseline
ctl365 baseline new windows --template autopilot --name RESO

# Generate with custom BitLocker name
ctl365 baseline new windows --template autopilot --name RESO \
  --bitlocker-policy-name "RESO BitLocker"

# Generate without updates
ctl365 baseline new windows --template autopilot --name RESO \
  --no-updates

# Apply baseline
ctl365 baseline apply --file baseline.json

# List available templates
ctl365 baseline list
```
