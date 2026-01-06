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
    configurations.push(generate_teams_calling_policies(args));

    // Teams VOIP configurations
    configurations.push(generate_teams_voicemail_config(args));
    configurations.push(generate_teams_call_queue_template(args));
    configurations.push(generate_teams_auto_attendant_template(args));

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

/// Teams: Calling policies with transcription enabled
fn generate_teams_calling_policies(args: &NewArgs) -> Value {
    json!({
        "type": "Teams.CallingPolicy",
        "name": format!("{} - Teams Calling Policy", args.name),
        "description": "Teams calling settings with transcription enabled for compliance",
        "settings": {
            "policyName": "Global",
            "allowPrivateCalling": true,
            "allowVoicemail": "UserOverride",
            "allowCallGroups": true,
            "allowDelegation": true,
            "allowCallForwardingToUser": true,
            "allowCallForwardingToPhone": true,
            "preventTollBypass": false,
            "busyOnBusyEnabledType": "Enabled",
            "musicOnHoldEnabledType": "Enabled",
            "allowWebPSTNCalling": true,
            "allowCloudRecordingForCalls": true,
            "allowTranscriptionForCalling": true, // Enable call transcription
            "liveCaptionsEnabledTypeForCalling": "EnabledUserOverride",
            "autoAnswerEnabledType": "Disabled",
            "spamFilteringEnabledType": "Enabled",
            "callRecordingExpirationDays": 60
        },
        "rationale": "Enables call transcription for compliance, audit trails, and accessibility. Recording retention set to 60 days.",
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "Set-CsTeamsCallingPolicy -Identity Global -AllowCloudRecordingForCalls $true -AllowTranscriptionForCalling $true -LiveCaptionsEnabledTypeForCalling EnabledUserOverride -SpamFilteringEnabledType Enabled"
            ]
        }
    })
}

/// Teams: Cloud voicemail configuration
fn generate_teams_voicemail_config(args: &NewArgs) -> Value {
    json!({
        "type": "Teams.VoicemailPolicy",
        "name": format!("{} - Teams Voicemail Policy", args.name),
        "description": "Cloud voicemail settings for Teams Phone users",
        "settings": {
            "enableVoicemail": true,
            "enableTranscription": true,
            "enableTranscriptionProfanityMasking": true,
            "enableTranscriptionTranslation": false,
            "maxVoicemailDuration": 300, // 5 minutes
            "shareDataForServiceImprovement": "Defer",
            "postAmble": "Thank you for calling. Your message has been recorded.",
            "enableEditingCallAnswerRulesSetting": true,
            "defaultVoicemailGreeting": "default",
            "sharedVoicemailEnabled": true // Enable shared voicemail for call queues
        },
        "prerequisites": [
            "Users must have Teams Phone license",
            "Create shared mailbox for shared voicemail (e.g., voicemail@domain.com)"
        ],
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "Set-CsOnlineVoicemailPolicy -Identity Global -EnableVoicemail $true -EnableTranscription $true -EnableTranscriptionProfanityMasking $true -MaximumRecordingLength 00:05:00",
                "# Create shared mailbox for voicemail",
                "New-Mailbox -Shared -Name 'Voicemail' -Alias 'voicemail' -DisplayName 'Company Voicemail'"
            ]
        }
    })
}

/// Teams: Call Queue template for VOIP setup
fn generate_teams_call_queue_template(args: &NewArgs) -> Value {
    json!({
        "type": "Teams.CallQueueTemplate",
        "name": format!("{} - Call Queue Template", args.name),
        "description": "Template for creating Teams Call Queues with best practices",
        "settings": {
            "templateName": "Standard Call Queue",
            "routingMethod": "RoundRobin", // Attendant, Serial, RoundRobin, LongestIdle
            "presenceBasedRouting": true,
            "conferenceMode": true, // Faster call connections
            "agentAlertTime": 30, // Seconds before routing to next agent
            "callOverflowThreshold": 50,
            "callOverflowAction": "Voicemail", // Disconnect, Voicemail, Forward, SharedVoicemail
            "callTimeoutThreshold": 1200, // 20 minutes max hold time
            "callTimeoutAction": "Voicemail",
            "enableOverflowSharedVoicemailTranscription": true,
            "enableTimeoutSharedVoicemailTranscription": true,
            "musicOnHoldAudioFile": "default",
            "welcomeMusicAudioFile": null,
            "languageId": "en-US",
            "greetingTextToSpeechPrompt": "Welcome to our company. Please hold while we connect you with the next available representative.",
            "optOutOfGlobalDirectory": false
        },
        "sharedVoicemail": {
            "enabled": true,
            "groupId": "voicemail@{domain}",
            "transcriptionEnabled": true,
            "suppressSystemGreeting": false
        },
        "agentOptOut": {
            "allowAgentOptOut": true
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "# Create resource account for the call queue",
                "New-CsOnlineApplicationInstance -UserPrincipalName mainline@domain.com -ApplicationId 11cd3e2e-fccb-42ad-ad00-878b93575e07 -DisplayName 'Main Line'",
                "# Create the call queue",
                "New-CsCallQueue -Name 'Main Line Queue' -RoutingMethod RoundRobin -AgentAlertTime 30 -AllowOptOut $true -ConferenceMode $true -PresenceBasedRouting $true -OverflowThreshold 50 -OverflowAction SharedVoicemail -TimeoutThreshold 1200 -TimeoutAction SharedVoicemail -OverflowSharedVoicemailTextToSpeechPrompt 'Please leave a message after the tone' -EnableOverflowSharedVoicemailTranscription $true",
                "# Assign phone number to resource account",
                "Set-CsPhoneNumberAssignment -Identity mainline@domain.com -PhoneNumber +1XXXXXXXXXX -PhoneNumberType DirectRouting"
            ],
            "graphApi": {
                "endpoint": "/communications/callQueues",
                "method": "POST"
            }
        }
    })
}

/// Teams: Auto Attendant template for VOIP setup
fn generate_teams_auto_attendant_template(args: &NewArgs) -> Value {
    json!({
        "type": "Teams.AutoAttendantTemplate",
        "name": format!("{} - Auto Attendant Template", args.name),
        "description": "Template for creating Teams Auto Attendants with business hours routing",
        "settings": {
            "templateName": "Standard Auto Attendant",
            "languageId": "en-US",
            "voiceId": "en-US-AriaNeural", // Neural TTS voice
            "enableVoiceResponse": true, // Enable voice (DTMF) input
            "enableTextToSpeech": true,
            "operatorEnabled": true,
            "operatorTarget": "CallQueue", // User, CallQueue, Voicemail
            "defaultCallFlow": {
                "greetingPromptType": "TextToSpeech",
                "greetingText": "Thank you for calling. Please listen to the following options.",
                "menuOptions": [
                    { "key": "1", "action": "TransferToCallQueue", "target": "Sales Queue", "voicePrompt": "For sales, press 1" },
                    { "key": "2", "action": "TransferToCallQueue", "target": "Support Queue", "voicePrompt": "For support, press 2" },
                    { "key": "0", "action": "TransferToOperator", "voicePrompt": "To speak with an operator, press 0" }
                ],
                "enableDialByName": true,
                "dialByNameScope": "InternalOnly"
            },
            "businessHours": {
                "schedule": "MonToFri-9to5",
                "timezone": "Eastern Standard Time",
                "monday": { "start": "09:00", "end": "17:00" },
                "tuesday": { "start": "09:00", "end": "17:00" },
                "wednesday": { "start": "09:00", "end": "17:00" },
                "thursday": { "start": "09:00", "end": "17:00" },
                "friday": { "start": "09:00", "end": "17:00" },
                "saturday": null,
                "sunday": null
            },
            "afterHoursCallFlow": {
                "greetingPromptType": "TextToSpeech",
                "greetingText": "Thank you for calling. Our office is currently closed. Our business hours are Monday through Friday, 9 AM to 5 PM Eastern Time.",
                "action": "Voicemail",
                "voicemailTarget": "voicemail@{domain}",
                "voicemailTranscription": true
            },
            "holidayCallFlow": {
                "enabled": true,
                "greetingText": "Thank you for calling. Our office is closed today for a holiday. Please leave a message and we will return your call on the next business day.",
                "action": "Voicemail"
            },
            "federalHolidays": generate_federal_holidays()
        },
        "implementation": {
            "method": "PowerShell",
            "commands": [
                "# Create resource account for auto attendant",
                "New-CsOnlineApplicationInstance -UserPrincipalName reception@domain.com -ApplicationId ce933385-9390-45d1-9512-c8d228074e07 -DisplayName 'Main Reception'",
                "# Create business hours schedule",
                "$schedule = New-CsOnlineSchedule -Name 'Business Hours' -WeeklyRecurrentSchedule -MondayHours @{Start='09:00';End='17:00'} -TuesdayHours @{Start='09:00';End='17:00'} -WednesdayHours @{Start='09:00';End='17:00'} -ThursdayHours @{Start='09:00';End='17:00'} -FridayHours @{Start='09:00';End='17:00'}",
                "# Create the auto attendant",
                "New-CsAutoAttendant -Name 'Main Reception' -LanguageId en-US -TimeZoneId 'Eastern Standard Time' -EnableVoiceResponse $true -Operator @{Id=(Get-CsCallQueue -Name 'Main Line Queue').Identity; Type='CallQueue'}",
                "# Assign phone number",
                "Set-CsPhoneNumberAssignment -Identity reception@domain.com -PhoneNumber +1XXXXXXXXXX -PhoneNumberType DirectRouting"
            ],
            "graphApi": {
                "endpoint": "/communications/autoAttendants",
                "method": "POST"
            }
        }
    })
}

/// Generate US Federal Holiday schedule for Auto Attendant
/// Calculates holidays for current year and next year
fn generate_federal_holidays() -> Value {
    use chrono::{Datelike, NaiveDate, Weekday};

    let current_year = chrono::Utc::now().year();
    let years = [current_year, current_year + 1];

    let mut holidays = Vec::new();

    for year in years {
        // New Year's Day - January 1 (observed on nearest weekday if weekend)
        holidays.push(json!({
            "name": format!("New Year's Day {}", year),
            "date": observed_date(year, 1, 1),
            "allDay": true
        }));

        // Martin Luther King Jr. Day - Third Monday of January
        holidays.push(json!({
            "name": format!("Martin Luther King Jr. Day {}", year),
            "date": nth_weekday_of_month(year, 1, Weekday::Mon, 3),
            "allDay": true
        }));

        // Presidents' Day - Third Monday of February
        holidays.push(json!({
            "name": format!("Presidents' Day {}", year),
            "date": nth_weekday_of_month(year, 2, Weekday::Mon, 3),
            "allDay": true
        }));

        // Memorial Day - Last Monday of May
        holidays.push(json!({
            "name": format!("Memorial Day {}", year),
            "date": last_weekday_of_month(year, 5, Weekday::Mon),
            "allDay": true
        }));

        // Juneteenth - June 19 (observed on nearest weekday if weekend)
        holidays.push(json!({
            "name": format!("Juneteenth {}", year),
            "date": observed_date(year, 6, 19),
            "allDay": true
        }));

        // Independence Day - July 4 (observed on nearest weekday if weekend)
        holidays.push(json!({
            "name": format!("Independence Day {}", year),
            "date": observed_date(year, 7, 4),
            "allDay": true
        }));

        // Labor Day - First Monday of September
        holidays.push(json!({
            "name": format!("Labor Day {}", year),
            "date": nth_weekday_of_month(year, 9, Weekday::Mon, 1),
            "allDay": true
        }));

        // Columbus Day - Second Monday of October
        holidays.push(json!({
            "name": format!("Columbus Day {}", year),
            "date": nth_weekday_of_month(year, 10, Weekday::Mon, 2),
            "allDay": true
        }));

        // Veterans Day - November 11 (observed on nearest weekday if weekend)
        holidays.push(json!({
            "name": format!("Veterans Day {}", year),
            "date": observed_date(year, 11, 11),
            "allDay": true
        }));

        // Thanksgiving Day - Fourth Thursday of November
        holidays.push(json!({
            "name": format!("Thanksgiving Day {}", year),
            "date": nth_weekday_of_month(year, 11, Weekday::Thu, 4),
            "allDay": true
        }));

        // Day After Thanksgiving (common business closure)
        let thanksgiving = nth_weekday_of_month(year, 11, Weekday::Thu, 4);
        if let Ok(tg_date) = NaiveDate::parse_from_str(&thanksgiving, "%Y-%m-%d") {
            holidays.push(json!({
                "name": format!("Day After Thanksgiving {}", year),
                "date": tg_date.succ_opt().map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                "allDay": true
            }));
        }

        // Christmas Eve (common business closure or early close)
        holidays.push(json!({
            "name": format!("Christmas Eve {}", year),
            "date": format!("{}-12-24", year),
            "allDay": false,
            "closeTime": "12:00" // Half day
        }));

        // Christmas Day - December 25 (observed on nearest weekday if weekend)
        holidays.push(json!({
            "name": format!("Christmas Day {}", year),
            "date": observed_date(year, 12, 25),
            "allDay": true
        }));

        // New Year's Eve (common early close)
        holidays.push(json!({
            "name": format!("New Year's Eve {}", year),
            "date": format!("{}-12-31", year),
            "allDay": false,
            "closeTime": "12:00" // Half day
        }));
    }

    json!({
        "schedule": holidays,
        "implementation": {
            "commands": [
                "# Create holiday call handling schedule",
                "$holidays = @()",
                "# Add each holiday date range to the schedule",
                "foreach ($holiday in $holidayList) { $holidays += New-CsOnlineDateTimeRange -Start $holiday.Start -End $holiday.End }",
                "New-CsOnlineSchedule -Name 'Federal Holidays' -FixedSchedule -DateTimeRanges $holidays"
            ]
        }
    })
}

/// Get the nth occurrence of a weekday in a month
fn nth_weekday_of_month(year: i32, month: u32, weekday: chrono::Weekday, n: u32) -> String {
    use chrono::{Datelike, NaiveDate};

    let first_of_month = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    let first_target_weekday = first_of_month
        .iter_days()
        .find(|d| d.weekday() == weekday)
        .unwrap();

    let target_date = first_target_weekday + chrono::Duration::weeks((n - 1) as i64);
    target_date.format("%Y-%m-%d").to_string()
}

/// Get the last occurrence of a weekday in a month
fn last_weekday_of_month(year: i32, month: u32, weekday: chrono::Weekday) -> String {
    use chrono::{Datelike, NaiveDate};

    // Get the last day of the month
    let next_month = if month == 12 { 1 } else { month + 1 };
    let next_year = if month == 12 { year + 1 } else { year };
    let first_of_next = NaiveDate::from_ymd_opt(next_year, next_month, 1).unwrap();
    let last_of_month = first_of_next.pred_opt().unwrap();

    // Work backwards to find the last target weekday
    let mut current = last_of_month;
    while current.weekday() != weekday {
        current = current.pred_opt().unwrap();
    }

    current.format("%Y-%m-%d").to_string()
}

/// Get the observed date for a fixed holiday (moves to Friday if Saturday, Monday if Sunday)
fn observed_date(year: i32, month: u32, day: u32) -> String {
    use chrono::{Datelike, NaiveDate, Weekday};

    let date = NaiveDate::from_ymd_opt(year, month, day).unwrap();
    let observed = match date.weekday() {
        Weekday::Sat => date.pred_opt().unwrap(), // Friday
        Weekday::Sun => date.succ_opt().unwrap(), // Monday
        _ => date,
    };

    observed.format("%Y-%m-%d").to_string()
}
