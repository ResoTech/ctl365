# 📧 Exchange Online Configuration Reference

This document provides reference material for configuring Exchange Online security settings via **ctl365**.

> **Note:** Exchange configuration will be implemented in **Phase 4/5** alongside Conditional Access and compliance features.

---

## 🎯 Overview

Exchange Online is a critical component of M365 security. **ctl365** will support automated configuration of:

- ✅ **Anti-spam policies** (aggressive filtering)
- ✅ **Anti-malware policies**
- ✅ **Anti-phishing policies** (ATP)
- ✅ **Safe Links & Safe Attachments** (Defender for Office 365)
- ✅ **Mail flow rules** (transport rules)
- ✅ **DKIM, SPF, DMARC** validation
- ✅ **Connection filters** (IP allow/block lists)
- ✅ **Outbound spam policies**

---

## 📚 Reference Materials

These settings are based on:
- **Microsoft Security Baselines** for Exchange Online
- **CIS Microsoft 365 Benchmark** (Exchange controls)
- **CISA ScubaGear** Exchange baseline
- **NCSC Cloud Security Guidance** for email security

See: [REFERENCE_ANALYSIS.md](../REFERENCE_ANALYSIS.md) for full baseline details.

---

## 🛡️ Anti-Spam Policy Configuration

### Baseline Settings (More Aggressive than Default)

**PowerShell Example:**
```powershell
Set-HostedContentFilterPolicy -Identity Default `
  -BulkThreshold 5 `
  -SpamAction MoveToJmf `
  -HighConfidenceSpamAction Quarantine `
  -PhishSpamAction Quarantine `
  -HighConfidencePhishAction Quarantine `
  -EnableEndUserSpamNotifications $true `
  -EndUserSpamNotificationFrequency 3 `
  -QuarantineRetentionPeriod 30
```

**Key Changes from Default:**
- **BulkThreshold**: 5 (more aggressive, default is 7)
- **HighConfidenceSpam**: Quarantine (default: MoveToJmf)
- **EnableEndUserSpamNotifications**: true (users can review quarantined mail)

---

## 🎣 Anti-Phishing Policy (ATP)

**Requires:** Microsoft Defender for Office 365 Plan 1 or 2

```powershell
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" `
  -EnableMailboxIntelligence $true `
  -EnableMailboxIntelligenceProtection $true `
  -MailboxIntelligenceProtectionAction Quarantine `
  -EnableSpoofIntelligence $true `
  -EnableTargetedUserProtection $true `
  -TargetedUsersToProtect "ceo@company.com","cfo@company.com" `
  -TargetedUserProtectionAction Quarantine `
  -PhishThresholdLevel 2
```

---

## 📨 Mail Flow Rules (Transport Rules)

### Block Executable Attachments

```powershell
New-TransportRule -Name "Block Executable Attachments" `
  -AttachmentExtensionMatchesWords @(".exe",".dll",".scr",".bat",".cmd") `
  -RejectMessageReasonText "Executable attachments are not permitted" `
  -RejectMessageEnhancedStatusCode "5.7.1"
```

### Block External Auto-Forwarding

```powershell
New-TransportRule -Name "Block External Auto-Forwarding" `
  -SentToScope NotInOrganization `
  -MessageTypeMatches AutoForward `
  -RejectMessageReasonText "External auto-forwarding is disabled" `
  -RejectMessageEnhancedStatusCode "5.7.1"
```

---

## 🔍 DKIM, SPF, DMARC Configuration

### SPF Record (DNS)
```
v=spf1 include:spf.protection.outlook.com -all
```

### DKIM Configuration
```powershell
New-DkimSigningConfig -DomainName yourcompany.com -Enabled $true
Set-DkimSigningConfig -Identity yourcompany.com -Enabled $true
```

### DMARC Record (DNS)
```
v=DMARC1; p=quarantine; rua=mailto:dmarc@yourcompany.com; fo=1
```

---

## 📤 Outbound Spam Policy

```powershell
Set-HostedOutboundSpamFilterPolicy -Identity Default `
  -RecipientLimitExternalPerHour 500 `
  -RecipientLimitPerDay 1000 `
  -ActionWhenThresholdReached BlockUserForToday `
  -AutoForwardingMode Off `
  -NotifyOutboundSpam $true
```

---

## 🚀 Planned ctl365 Commands

```bash
ctl365 exchange apply-baseline --aggressive
ctl365 exchange spam-policy --bulk-threshold 5
ctl365 exchange anti-phish --protect-users ceo@company.com
ctl365 exchange block-attachments --extensions exe,dll,scr
ctl365 exchange block-forwarding --external
ctl365 exchange dkim-enable --domain yourcompany.com
ctl365 exchange validate-auth --domain yourcompany.com
ctl365 audit --product exchange --standard cis
```

---

**This document will be used as reference when implementing Exchange features in ctl365 Phase 4/5.**

**ctl365** — *Control your cloud. Define your baseline.* 📧
