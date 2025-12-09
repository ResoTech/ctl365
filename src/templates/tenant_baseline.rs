/// Tenant-Wide Microsoft 365 Baseline Configuration
///
/// Handles tenant-level settings across Exchange Online, SharePoint, Teams, etc.
/// These are organization-wide settings that apply to all users/resources
use crate::cmd::baseline::NewArgs;
use crate::error::Result;
use serde_json::{Value, json};

/// Generate complete tenant baseline configuration
pub fn generate_tenant_baseline(args: &NewArgs) -> Result<Value> {
    let mut configurations = Vec::new();

    // Exchange Online configurations
    configurations.push(generate_exchange_archive_config(args));
    configurations.push(generate_exchange_retention_policy(args));
    configurations.push(generate_antispam_config(args));
    configurations.push(generate_antimalware_config(args));
    configurations.push(generate_outbound_spam_config(args));

    // Defender for Office 365 (if applicable)
    if args.defender {
        configurations.push(generate_safe_links_config(args));
        configurations.push(generate_safe_attachments_config(args));
    }

    // SharePoint/OneDrive configurations
    configurations.push(generate_sharepoint_sharing_config(args));
    configurations.push(generate_onedrive_sync_restrictions(args));

    // Teams configurations
    configurations.push(generate_teams_external_access_config(args));
    configurations.push(generate_teams_meeting_policies(args));

    Ok(json!({
        "version": "1.0",
        "template": "tenant-baseline",
        "platform": "tenant-wide",
        "metadata": {
            "description": "Tenant-wide Microsoft 365 security baseline",
            "source": "ctl365",
            "generated": chrono::Utc::now().to_rfc3339(),
            "name": &args.name
        },
        "configurations": configurations
    }))
}

/// Exchange Online: Enable archive mailboxes for all users
fn generate_exchange_archive_config(args: &NewArgs) -> Value {
    json!({
        "type": "ExchangeOnline.ArchiveMailbox",
        "name": format!("{} - Archive Mailbox - Tenant Wide", args.name),
        "description": "Enable archive mailbox for all licensed users",
        "settings": {
            "scope": "AllUsers",
            "enableArchive": true,
            "autoExpandingArchive": true, // Unlimited archive storage
            "archiveQuotaGB": 100,
            "archiveWarningQuotaGB": 90
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "Connect-ExchangeOnline",
                "Get-Mailbox -ResultSize Unlimited | Enable-Mailbox -Archive",
                "Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AutoExpandingArchive"
            ]
        }
    })
}

/// Exchange Online: Retention policy - Archive after 3 years
fn generate_exchange_retention_policy(args: &NewArgs) -> Value {
    let archive_years = 3;

    json!({
        "type": "ExchangeOnline.RetentionPolicy",
        "name": format!("{} - Retention Policy - Archive After {} Years", args.name, archive_years),
        "description": format!("Move emails to archive after {} years", archive_years),
        "settings": {
            "policyName": format!("Archive-{}-Year-Policy", archive_years),
            "retentionTags": [
                {
                    "name": format!("{} Year Archive Tag", archive_years),
                    "type": "All",
                    "ageLimitForRetention": archive_years * 365,
                    "retentionAction": "MoveToArchive",
                    "retentionEnabled": true
                },
                {
                    "name": "Deleted Items - 30 Days",
                    "type": "DeletedItems",
                    "ageLimitForRetention": 30,
                    "retentionAction": "PermanentlyDelete",
                    "retentionEnabled": true
                },
                {
                    "name": "Junk Email - 30 Days",
                    "type": "JunkEmail",
                    "ageLimitForRetention": 30,
                    "retentionAction": "PermanentlyDelete",
                    "retentionEnabled": true
                }
            ],
            "applyToAllMailboxes": true
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                format!("New-RetentionPolicyTag 'Archive-{}-Year' -Type All -AgeLimitForRetention {} -RetentionAction MoveToArchive", archive_years, archive_years * 365),
                format!("New-RetentionPolicy 'Default-Archive-Policy' -RetentionPolicyTagLinks 'Archive-{}-Year'", archive_years),
                "Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetentionPolicy 'Default-Archive-Policy'"
            ]
        }
    })
}

/// Exchange Online: Anti-spam configuration
fn generate_antispam_config(args: &NewArgs) -> Value {
    json!({
        "type": "ExchangeOnline.AntiSpam",
        "name": format!("{} - Anti-Spam Policy", args.name),
        "description": "Tenant-wide spam filtering with strict settings",
        "settings": {
            "policyName": "Strict Anti-Spam Policy",
            "bulkThreshold": 6, // Lower = more aggressive
            "spamAction": "MoveToJmf", // Move to Junk Mail Folder
            "highConfidenceSpamAction": "Quarantine",
            "phishAction": "Quarantine",
            "highConfidencePhishAction": "Quarantine",
            "bulkAction": "MoveToJmf",
            "quarantineRetentionPeriod": 30,
            "endUserSpamNotifications": false, // Disable per user request
            "endUserSpamNotificationFrequency": 0,
            "increaseSCL": {
                "imageLinks": true,
                "numericIPs": true,
                "redirectToOtherPort": true,
                "webBugs": true
            },
            "markAsSpam": {
                "ndrBackscatter": true,
                "spfRecordHardFail": true,
                "fromAddressAuthFail": true,
                "emptyMessages": true,
                "javaScriptInHtml": true,
                "frameOrIframe": true,
                "objectTagsInHtml": true,
                "embedTags": true,
                "formTags": true,
                "sensitiveWords": true
            },
            "allowedSenders": [],
            "allowedDomains": [],
            "blockedSenders": [],
            "blockedDomains": []
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "New-HostedContentFilterPolicy -Name 'Strict Anti-Spam Policy' -BulkThreshold 6 -SpamAction MoveToJmf -HighConfidenceSpamAction Quarantine -EnableEndUserSpamNotifications $false",
                "New-HostedContentFilterRule -Name 'Strict Anti-Spam Rule' -HostedContentFilterPolicy 'Strict Anti-Spam Policy' -RecipientDomainIs (Get-AcceptedDomain).Name"
            ]
        }
    })
}

/// Exchange Online: Anti-malware configuration
fn generate_antimalware_config(args: &NewArgs) -> Value {
    json!({
        "type": "ExchangeOnline.AntiMalware",
        "name": format!("{} - Anti-Malware Policy", args.name),
        "description": "Block malicious attachments and file types",
        "settings": {
            "policyName": "Strict Anti-Malware Policy",
            "enableFileFilter": true,
            "enableZap": true, // Zero-hour Auto Purge
            "zapEnabled": true,
            "enableInternalSenderNotifications": false,
            "enableExternalSenderNotifications": false,
            "enableInternalAdminNotifications": true,
            "internalSenderAdminAddress": "security@example.com",
            "fileTypes": [
                "ace", "ani", "app", "cab", "cpl", "dll", "docm", "exe",
                "jar", "js", "jse", "lib", "lnk", "mde", "msc", "msi",
                "msp", "mst", "pif", "ps1", "scr", "sct", "shb", "sys",
                "vb", "vbe", "vbs", "vxd", "wsc", "wsf", "wsh", "xlsm", "pptm"
            ],
            "action": "Reject" // Reject messages with blocked file types
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "New-MalwareFilterPolicy -Name 'Strict Anti-Malware Policy' -EnableFileFilter $true -ZapEnabled $true -FileTypes @('exe','dll','vbs','js','jar')",
                "New-MalwareFilterRule -Name 'Strict Anti-Malware Rule' -MalwareFilterPolicy 'Strict Anti-Malware Policy' -RecipientDomainIs (Get-AcceptedDomain).Name"
            ]
        }
    })
}

/// Exchange Online: Outbound spam filter policy
fn generate_outbound_spam_config(args: &NewArgs) -> Value {
    json!({
        "type": "ExchangeOnline.OutboundSpam",
        "name": format!("{} - Outbound Spam Policy", args.name),
        "description": "Prevent compromised accounts from sending spam",
        "settings": {
            "recipientLimitExternalPerHour": 500,
            "recipientLimitInternalPerHour": 1000,
            "recipientLimitPerDay": 1000,
            "actionWhenThresholdReached": "BlockUser",
            "autoForwardingMode": "Off", // Critical: Prevent auto-forwarding to external domains
            "notifyOutboundSpam": true,
            "notifyOutboundSpamRecipients": ["security@example.com"],
            "bccSuspiciousOutboundMail": false,
            "bccSuspiciousOutboundAdditionalRecipients": []
        },
        "rationale": "Blocks external auto-forwarding to prevent data exfiltration via compromised accounts",
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off -ActionWhenThresholdReached BlockUser -RecipientLimitExternalPerHour 500"
            ]
        }
    })
}

/// Defender for Office 365: Safe Links
fn generate_safe_links_config(args: &NewArgs) -> Value {
    json!({
        "type": "DefenderForOffice365.SafeLinks",
        "name": format!("{} - Safe Links Policy", args.name),
        "description": "Real-time URL scanning in emails and Office apps",
        "settings": {
            "policyName": "Strict Safe Links Policy",
            "isEnabled": true,
            "scanUrls": true,
            "enableForInternalSenders": true,
            "deliverMessageAfterScan": true,
            "disableUrlRewrite": false,
            "trackClicks": true,
            "enableSafeLinksForEmail": true,
            "enableSafeLinksForTeams": true,
            "enableSafeLinksForOffice": true,
            "doNotRewriteUrls": [],
            "doNotTrackUserClicks": false
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "New-SafeLinksPolicy -Name 'Strict Safe Links Policy' -EnableSafeLinksForEmail $true -EnableSafeLinksForTeams $true -EnableSafeLinksForOffice $true -TrackClicks $true",
                "New-SafeLinksRule -Name 'Strict Safe Links Rule' -SafeLinksPolicy 'Strict Safe Links Policy' -RecipientDomainIs (Get-AcceptedDomain).Name"
            ]
        }
    })
}

/// Defender for Office 365: Safe Attachments
fn generate_safe_attachments_config(args: &NewArgs) -> Value {
    json!({
        "type": "DefenderForOffice365.SafeAttachments",
        "name": format!("{} - Safe Attachments Policy", args.name),
        "description": "Sandbox attachments before delivery",
        "settings": {
            "policyName": "Strict Safe Attachments Policy",
            "isEnabled": true,
            "action": "DynamicDelivery", // Deliver message immediately, attach when scan completes
            "redirect": false,
            "actionOnError": true,
            "enableForInternalSenders": true,
            "scanTimeout": 30
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "New-SafeAttachmentPolicy -Name 'Strict Safe Attachments Policy' -Enable $true -Action DynamicDelivery -ActionOnError $true",
                "New-SafeAttachmentRule -Name 'Strict Safe Attachments Rule' -SafeAttachmentPolicy 'Strict Safe Attachments Policy' -RecipientDomainIs (Get-AcceptedDomain).Name"
            ]
        }
    })
}

/// SharePoint Online: External sharing restrictions
fn generate_sharepoint_sharing_config(args: &NewArgs) -> Value {
    json!({
        "type": "SharePointOnline.SharingPolicy",
        "name": format!("{} - SharePoint Sharing Policy", args.name),
        "description": "Restrict external sharing for data loss prevention",
        "settings": {
            "sharingCapability": "ExistingExternalUserSharingOnly", // Only existing guests
            "requireAnonymousLinksExpireInDays": 30,
            "fileAnonymousLinkType": "View", // View-only for anonymous links
            "folderAnonymousLinkType": "View",
            "defaultSharingLinkType": "Internal", // Default to internal sharing
            "defaultLinkPermission": "View",
            "preventExternalUsersFromResharing": true,
            "notifyOwnersWhenItemsReshared": true,
            "showPeoplePickerSuggestionsForGuestUsers": false
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "Connect-SPOService -Url https://[tenant]-admin.sharepoint.com",
                "Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly -DefaultSharingLinkType Internal -RequireAnonymousLinksExpireInDays 30"
            ]
        }
    })
}

/// OneDrive: Sync client restrictions
fn generate_onedrive_sync_restrictions(args: &NewArgs) -> Value {
    json!({
        "type": "OneDrive.SyncRestrictions",
        "name": format!("{} - OneDrive Sync Policy", args.name),
        "description": "Restrict OneDrive sync to managed devices only",
        "settings": {
            "blockMacSync": false,
            "excludedFileExtensions": ["exe", "dll", "bat", "cmd", "ps1"],
            "allowedTenantIds": [], // Allow sync from this tenant only
            "blockPersonalAccounts": true, // Block personal OneDrive accounts
            "requireDeviceCompliance": true
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "Set-SPOTenantSyncClientRestriction -Enable -DomainGuids $TenantId"
            ]
        }
    })
}

/// Teams: External access configuration
fn generate_teams_external_access_config(args: &NewArgs) -> Value {
    json!({
        "type": "Teams.ExternalAccess",
        "name": format!("{} - Teams External Access Policy", args.name),
        "description": "Control Teams external communication",
        "settings": {
            "allowFederatedUsers": true,
            "allowTeamsConsumer": false, // Block personal Teams accounts
            "allowPublicUsers": false, // Block Skype users
            "allowedDomains": [], // Whitelist specific domains if needed
            "blockedDomains": []
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "Set-CsExternalAccessPolicy -Identity Global -EnableFederationAccess $true -EnablePublicCloudAccess $false"
            ]
        }
    })
}

/// Teams: Meeting policies
fn generate_teams_meeting_policies(args: &NewArgs) -> Value {
    json!({
        "type": "Teams.MeetingPolicy",
        "name": format!("{} - Teams Meeting Policy", args.name),
        "description": "Secure Teams meeting settings",
        "settings": {
            "allowAnonymousUsersToJoinMeeting": false,
            "allowAnonymousUsersToStartMeeting": false,
            "autoAdmittedUsers": "EveryoneInCompanyExcludingGuests",
            "allowPSTNUsersToBypassLobby": false,
            "allowCloudRecording": true,
            "allowRecordingStorageOutsideRegion": false,
            "allowOutlookAddIn": true,
            "allowPowerPointSharing": true,
            "allowExternalParticipantGiveRequestControl": false,
            "allowWhiteboard": true,
            "allowSharedNotes": true,
            "allowTranscription": true,
            "mediaEncryption": "SupportEncryption",
            "allowIPVideo": true,
            "screenSharingMode": "EntireScreen"
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "Set-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers 'EveryoneInCompanyExcludingGuests' -AllowAnonymousUsersToJoinMeeting $false"
            ]
        }
    })
}
