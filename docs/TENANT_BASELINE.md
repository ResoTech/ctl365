# Tenant-Wide Microsoft 365 Baseline Configuration

Complete guide for deploying tenant-wide security settings across Exchange Online, SharePoint, OneDrive, and Microsoft Teams.

---

## 📋 Overview

The tenant baseline configures organization-level settings that apply to **all users** in your Microsoft 365 tenant. These settings complement device-specific baselines (Windows, macOS) and provide defense-in-depth security.

### What Gets Configured

#### Exchange Online
- **Archive Mailboxes**: Enable for all licensed users with unlimited auto-expanding storage
- **Retention Policies**: Archive emails after 3 years (configurable)
- **Anti-Spam**: Strict spam filtering with quarantine for high-confidence threats
- **Anti-Malware**: Block dangerous file types and enable Zero-hour Auto Purge (ZAP)
- **Outbound Spam Filter**: Block external auto-forwarding to prevent data exfiltration
- **Quarantine Notifications**: Disable end-user notifications (admin-managed quarantine)

#### Defender for Office 365 (Optional)
- **Safe Links**: Real-time URL scanning in emails, Teams, and Office apps
- **Safe Attachments**: Sandbox attachments before delivery (Dynamic Delivery)

#### SharePoint Online
- **External Sharing**: Restrict to existing guests only
- **Anonymous Links**: 30-day expiration, view-only by default
- **Default Sharing**: Internal-only by default

#### OneDrive for Business
- **Sync Restrictions**: Block personal OneDrive accounts
- **Compliance Integration**: Require device compliance for sync

#### Microsoft Teams
- **External Access**: Block consumer Teams and Skype users
- **Meeting Security**: Auto-admit company users only, block anonymous join

---

## 🚀 Quick Start

### Prerequisites

1. **Licenses Required**:
   - Exchange Online (included in M365 Business/Enterprise)
   - Defender for Office 365 Plan 1/2 (optional, for Safe Links/Attachments)

2. **Permissions Required**:
   - Exchange Administrator
   - Security Administrator
   - SharePoint Administrator
   - Teams Administrator
   - **OR** Global Administrator

3. **Active Tenant Configured**:
   ```bash
   ctl365 tenant add production --tenant-id <id> --client-id <id>
   ctl365 login --tenant production
   ```

---

## 📦 Deployment Options

### Option 1: Full Tenant Baseline (Recommended)

Deploy all tenant-wide security settings:

```bash
ctl365 tenant configure \
  --all \
  --name "Production" \
  --defender-office
```

**What This Does**:
- ✓ Enables archive mailboxes for all users
- ✓ Configures 3-year retention policy
- ✓ Disables quarantine email notifications
- ✓ Configures strict anti-spam policies
- ✓ Configures anti-malware policies
- ✓ Blocks external auto-forwarding
- ✓ Enables Defender for Office 365 (Safe Links/Attachments)

### Option 2: Selective Configuration

Deploy only specific features:

#### Exchange Archive Mailboxes Only
```bash
ctl365 tenant configure \
  --enable-archive \
  --archive-after-years 3 \
  --name "Production"
```

#### Spam Filtering Only
```bash
ctl365 tenant configure \
  --configure-spam-filter \
  --disable-quarantine-alerts \
  --name "Production"
```

#### Defender for Office 365 Only
```bash
ctl365 tenant configure \
  --defender-office \
  --name "Production"
```

### Option 3: Generate Baseline File (No Deployment)

Generate a baseline configuration file for review:

```bash
ctl365 tenant configure \
  --all \
  --defender-office \
  --output tenant-baseline.json
```

Review the generated JSON, then manually apply via PowerShell or Intune admin center.

---

## 🔧 Detailed Configuration

### Exchange Online Archive Mailboxes

**What It Does**:
- Enables In-Place Archive for all licensed users
- Provides unlimited storage via auto-expanding archives
- Escrows archive access to Entra ID for IT recovery

**Command**:
```bash
ctl365 tenant configure \
  --enable-archive \
  --archive-after-years 3
```

**User Impact**:
- Users see "Online Archive" folder in Outlook
- Emails older than 3 years automatically move to archive
- Transparent to user experience

**PowerShell Equivalent**:
```powershell
Get-Mailbox -ResultSize Unlimited | Enable-Mailbox -Archive
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AutoExpandingArchive
```

---

### Retention Policy (Archive After X Years)

**What It Does**:
- Automatically moves emails to archive after specified years (default: 3)
- Permanently deletes Deleted Items after 30 days
- Permanently deletes Junk Email after 30 days

**Command**:
```bash
ctl365 tenant configure \
  --enable-archive \
  --archive-after-years 5  # Custom: 5 years instead of 3
```

**Retention Tags Created**:
1. **Default Policy Tag**: Move to Archive after X years
2. **Deleted Items**: Permanently delete after 30 days
3. **Junk Email**: Permanently delete after 30 days

**PowerShell Equivalent**:
```powershell
New-RetentionPolicyTag "Archive-3-Year" -Type All -AgeLimitForRetention 1095 -RetentionAction MoveToArchive
New-RetentionPolicy "Default-Archive-Policy" -RetentionPolicyTagLinks "Archive-3-Year"
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetentionPolicy "Default-Archive-Policy"
```

---

### Anti-Spam Configuration

**What It Does**:
- Moves spam to Junk Mail folder
- Quarantines high-confidence spam and phishing
- Disables end-user quarantine notifications (admin-managed)
- Aggressive spam detection settings

**Command**:
```bash
ctl365 tenant configure \
  --configure-spam-filter \
  --disable-quarantine-alerts
```

**Policy Settings**:
- **Bulk Threshold**: 6 (aggressive)
- **Spam Action**: Move to Junk Mail Folder
- **High Confidence Spam**: Quarantine
- **Phishing**: Quarantine
- **High Confidence Phishing**: Quarantine
- **End-User Notifications**: Disabled

**Advanced Settings**:
- Mark as spam: NDR backscatter, SPF hard fail, auth failures
- Increase SCL: Image links, numeric IPs, redirects, web bugs
- Block: JavaScript, frames, form tags, embedded objects

**PowerShell Equivalent**:
```powershell
New-HostedContentFilterPolicy -Name "Strict Anti-Spam" `
  -BulkThreshold 6 `
  -SpamAction MoveToJmf `
  -HighConfidenceSpamAction Quarantine `
  -EnableEndUserSpamNotifications $false
```

---

### Outbound Spam Filter (Data Loss Prevention)

**What It Does**:
- **Blocks external auto-forwarding** (critical security control)
- Limits recipient counts to prevent spam from compromised accounts
- Automatically blocks accounts when limits exceeded

**Command**:
```bash
ctl365 tenant configure --configure-spam-filter
```

**Policy Settings**:
- **Auto-Forwarding**: OFF (blocks external forwarding rules)
- **External Recipients/Hour**: 500
- **Internal Recipients/Hour**: 1000
- **Recipients/Day**: 1000
- **Action**: Block user account when threshold reached

**Why This Matters**:
Compromised accounts often create auto-forwarding rules to exfiltrate data. This setting **blocks all external auto-forwarding** to prevent data loss.

**PowerShell Equivalent**:
```powershell
Set-HostedOutboundSpamFilterPolicy -Identity Default `
  -AutoForwardingMode Off `
  -ActionWhenThresholdReached BlockUser
```

---

### Defender for Office 365: Safe Links

**What It Does**:
- Real-time URL scanning when users click links
- Rewrites URLs to proxy through Microsoft's scanning service
- Tracks user clicks for threat intelligence
- Protects in: Emails, Teams messages, Office documents

**Command**:
```bash
ctl365 tenant configure --defender-office
```

**Policy Settings**:
- **Scan URLs**: Enabled
- **Enable for Internal Senders**: Yes
- **Deliver Message After Scan**: Yes (no delay)
- **Track User Clicks**: Yes
- **Protection in**: Email, Teams, Office apps

**User Experience**:
- Links rewritten to: `https://nam02.safelinks.protection.outlook.com/?url=...`
- Click-time verification (real-time threat check)
- Warning page shown if URL is malicious

**PowerShell Equivalent**:
```powershell
New-SafeLinksPolicy -Name "Strict Safe Links" `
  -EnableSafeLinksForEmail $true `
  -EnableSafeLinksForTeams $true `
  -EnableSafeLinksForOffice $true `
  -TrackClicks $true
```

---

### Defender for Office 365: Safe Attachments

**What It Does**:
- Sandboxes attachments in isolated environment
- Delivers message immediately, attaches file when scan completes (Dynamic Delivery)
- Blocks malicious attachments before user can open

**Command**:
```bash
ctl365 tenant configure --defender-office
```

**Policy Settings**:
- **Action**: Dynamic Delivery (fast user experience)
- **Enable for Internal Senders**: Yes
- **Action on Error**: Apply protection even if scan errors

**User Experience**:
- Email delivered immediately
- Placeholder shown for attachment: "Scanning..."
- Attachment replaced with actual file when scan completes (~5 minutes)
- If malicious: Attachment removed, warning shown

**PowerShell Equivalent**:
```powershell
New-SafeAttachmentPolicy -Name "Strict Safe Attachments" `
  -Enable $true `
  -Action DynamicDelivery `
  -ActionOnError $true
```

---

## 🔍 Verification

### Check Applied Configuration

```bash
ctl365 tenant show
```

**Output Example**:
```
Exchange Online Settings:
  Anti-spam policies: 2
  Organization: Contoso Corporation
```

### Verify in Microsoft 365 Admin Center

1. **Exchange Admin Center**: https://admin.exchange.microsoft.com
   - **Mail flow** → **Rules**: Check transport rules
   - **Protection** → **Anti-spam**: Verify policies applied
   - **Protection** → **Anti-malware**: Verify policies applied
   - **Recipients** → **Mailboxes**: Spot-check archive enabled

2. **Microsoft 365 Defender Portal**: https://security.microsoft.com
   - **Email & collaboration** → **Policies & rules**
   - **Safe Links**: Verify policy exists and is assigned to all users
   - **Safe Attachments**: Verify policy exists and is assigned to all users

3. **Test User Mailbox**:
   ```powershell
   Get-Mailbox -Identity user@example.com | Format-List ArchiveStatus, RetentionPolicy
   ```

   Expected output:
   ```
   ArchiveStatus   : Active
   RetentionPolicy : Default-Archive-Policy
   ```

---

## ⚠️ Important Notes

### Data Sovereignty

Archive mailboxes and retention policies respect your tenant's data residency:
- Data stays in your geographic region (EU, US, APAC, etc.)
- Archive storage uses same encryption as primary mailbox
- Recovery keys escrowed to Entra ID

### License Requirements

| Feature | License Required |
|---------|------------------|
| Archive Mailbox | Exchange Online Plan 2 or M365 E3/E5 |
| Unlimited Archive | Exchange Online Archiving add-on |
| Safe Links | Defender for Office 365 Plan 1 or M365 E5 |
| Safe Attachments | Defender for Office 365 Plan 1 or M365 E5 |
| Anti-spam (basic) | All Exchange Online licenses |

### User Impact

**Low Impact**:
- Archive mailbox enablement (transparent)
- Retention policies (automatic archival)
- Safe Links (slight URL rewrite, no delays)

**Medium Impact**:
- Outbound spam filter (blocks external auto-forwarding)
  - Users with legitimate external forwards will need admin assistance
  - Create exceptions via transport rules if needed

**No Impact**:
- Anti-spam policies (server-side filtering)
- Anti-malware policies (server-side filtering)

---

## 🔄 Rollback / Exceptions

### Disable Auto-Forwarding Block for Specific Users

If legitimate business need for external auto-forwarding:

```powershell
# Create transport rule exception
New-TransportRule -Name "Allow External Forward - Executive Team" `
  -From @("ceo@example.com", "cfo@example.com") `
  -SetHeaderName "X-MS-Exchange-Organization-AllowedToForward" `
  -SetHeaderValue "True"
```

### Remove Retention Policy from User

```powershell
Set-Mailbox -Identity user@example.com -RetentionPolicy $null
```

### Disable Safe Links for Testing

Not recommended, but possible:

```powershell
Remove-SafeLinksRule -Identity "Strict Safe Links Rule"
```

---

## 🚨 Troubleshooting

### Issue: Archive Mailbox Not Enabled

**Symptoms**: User doesn't see "Online Archive" in Outlook

**Causes**:
- User doesn't have proper license
- Archive feature not enabled on license
- Provisioning delay (up to 24 hours)

**Solution**:
```powershell
# Check license
Get-Mailbox -Identity user@example.com | Format-List LicenseAssignment

# Manually enable
Enable-Mailbox -Identity user@example.com -Archive
```

### Issue: Emails Not Moving to Archive

**Symptoms**: Emails older than 3 years still in primary mailbox

**Causes**:
- Retention policy not applied
- Managed Folder Assistant hasn't run yet (runs every 7 days by default)

**Solution**:
```powershell
# Force Managed Folder Assistant to run
Start-ManagedFolderAssistant -Identity user@example.com
```

### Issue: Safe Links Breaking Internal URLs

**Symptoms**: Internal company URLs rewritten and broken

**Solution**: Add to Safe Links "Do Not Rewrite" list:
```powershell
Set-SafeLinksPolicy -Identity "Strict Safe Links" `
  -DoNotRewriteUrls @("*.internal.company.com", "intranet.company.com")
```

### Issue: Safe Attachments Causing Delays

**Symptoms**: Attachments take too long to become available

**Solution**: Switch from "Dynamic Delivery" to "Monitor" for specific groups:
```powershell
# Create exception policy for executive team
New-SafeAttachmentPolicy -Name "Executive - Monitor Only" `
  -Enable $true `
  -Action Allow # Monitor but don't delay
```

---

## 📊 Monitoring & Reporting

### Exchange Online Protection Reports

**Location**: https://security.microsoft.com → **Email & collaboration** → **Reports**

**Key Reports**:
1. **Threat protection status**: Phishing/spam blocked
2. **Mail flow status**: Inbound/outbound volumes
3. **Top senders and recipients**: Identify compromised accounts
4. **Spam detections**: Review false positives

### Archive Usage Reports

```powershell
# Get archive mailbox sizes
Get-Mailbox -ResultSize Unlimited | Get-MailboxStatistics -Archive |
  Select DisplayName, TotalItemSize, ItemCount |
  Export-Csv archive-usage.csv
```

### Safe Links & Safe Attachments Reports

**Location**: https://security.microsoft.com → **Reports** → **Email & collaboration**

**Metrics**:
- URLs clicked and blocked
- Attachments detonated
- Threats detected
- User click patterns

---

## ✅ Deployment Checklist

- [ ] Review license assignments (Archive, Defender for Office 365)
- [ ] Generate baseline configuration for review
- [ ] Test deployment in pilot tenant (if available)
- [ ] Deploy to production with `--dry-run` first
- [ ] Apply configuration to production
- [ ] Verify policies in admin centers
- [ ] Test with pilot user group (5-10 users)
- [ ] Monitor Exchange admin center for 48 hours
- [ ] Review Defender for Office 365 reports
- [ ] Document exceptions (if any external forwarding needed)
- [ ] Train IT staff on quarantine management
- [ ] Communicate archive mailbox feature to users

---

## 🎓 User Communication

### Sample Email to Users

**Subject**: New Email Security Features - Archive Mailbox Enabled

**Body**:

Hi Team,

We've enabled new email security features to protect our organization:

**What's New:**
- **Archive Mailbox**: Emails older than 3 years will automatically move to your "Online Archive" folder in Outlook. You can still search and access these emails—they're just stored separately to keep your inbox fast.

- **Enhanced Spam Protection**: More aggressive spam filtering will reduce junk email. If a legitimate email gets quarantined, contact IT.

- **Link Protection**: When you click links in emails, they'll be scanned in real-time to block malicious websites.

**What You Need to Do:**
- Nothing! These features work automatically.
- If you had external email forwarding rules, they've been disabled for security. Contact IT if you have a business need for external forwarding.

**Questions?**
Contact IT Support: support@example.com

---

## 🔗 Related Documentation

- [Windows Baseline Deployment](WINDOWS_DEPLOYMENT.md)
- [macOS Baseline Deployment](MACOS_DEPLOYMENT.md)
- [Conditional Access Deployment](CONDITIONAL_ACCESS.md)

---

**Ready to deploy?**

```bash
ctl365 tenant configure --all --defender-office --name "Production"
```

🎉 **Your tenant is now enterprise-secured!**
