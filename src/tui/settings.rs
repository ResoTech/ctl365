//! Tenant settings definitions and defaults
//!
//! Defines all configurable tenant settings with metadata for TUI display.

use serde::{Deserialize, Serialize};

/// Categories of tenant settings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingCategory {
    DefenderForOffice365,
    ExchangeOnline,
    SharePointOneDrive,
    Teams,
    ConditionalAccess,
    IntuneBaseline,
}

impl std::fmt::Display for SettingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DefenderForOffice365 => write!(f, "Defender for Office 365"),
            Self::ExchangeOnline => write!(f, "Exchange Online"),
            Self::SharePointOneDrive => write!(f, "SharePoint & OneDrive"),
            Self::Teams => write!(f, "Microsoft Teams"),
            Self::ConditionalAccess => write!(f, "Conditional Access"),
            Self::IntuneBaseline => write!(f, "Intune Baseline"),
        }
    }
}

/// A configurable tenant setting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSetting {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub setting_type: SettingType,
    pub default_value: SettingValue,
    pub current_value: Option<SettingValue>,
    pub recommended: bool,
    pub cis_control: Option<String>,
    pub scuba_control: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SettingType {
    Boolean,
    String,
    Number { min: Option<i64>, max: Option<i64> },
    Choice { options: Vec<String> },
    MultiChoice { options: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SettingValue {
    Boolean(bool),
    String(String),
    Number(i64),
    List(Vec<String>),
}

impl std::fmt::Display for SettingValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boolean(b) => write!(f, "{}", if *b { "Enabled" } else { "Disabled" }),
            Self::String(s) => write!(f, "{}", s),
            Self::Number(n) => write!(f, "{}", n),
            Self::List(l) => write!(f, "{}", l.join(", ")),
        }
    }
}

/// All Defender for Office 365 settings
pub fn defender_settings() -> Vec<TenantSetting> {
    vec![
        TenantSetting {
            id: "safe_links_enabled".into(),
            name: "Enable Safe Links".into(),
            description: "Scan URLs in emails and Office documents in real-time".into(),
            category: "Defender for Office 365".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("2.1.1".into()),
            scuba_control: Some("MS.DEFENDER.1.1v1".into()),
        },
        TenantSetting {
            id: "safe_links_scan_urls".into(),
            name: "URL Scanning".into(),
            description: "Scan URLs at time of click (real-time protection)".into(),
            category: "Defender for Office 365".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("2.1.1".into()),
            scuba_control: Some("MS.DEFENDER.1.2v1".into()),
        },
        TenantSetting {
            id: "safe_links_teams".into(),
            name: "Safe Links for Teams".into(),
            description: "Protect URLs shared in Microsoft Teams chats and channels".into(),
            category: "Defender for Office 365".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("2.1.2".into()),
            scuba_control: Some("MS.DEFENDER.1.3v1".into()),
        },
        TenantSetting {
            id: "safe_links_office".into(),
            name: "Safe Links for Office Apps".into(),
            description: "Protect URLs in Word, Excel, PowerPoint documents".into(),
            category: "Defender for Office 365".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("2.1.3".into()),
            scuba_control: None,
        },
        TenantSetting {
            id: "safe_links_track_clicks".into(),
            name: "Track User Clicks".into(),
            description: "Log when users click on URLs for security analysis".into(),
            category: "Defender for Office 365".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: None,
        },
        TenantSetting {
            id: "safe_links_internal_senders".into(),
            name: "Scan Internal Sender URLs".into(),
            description: "Also scan URLs from internal/trusted senders".into(),
            category: "Defender for Office 365".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: None,
        },
        TenantSetting {
            id: "safe_attachments_enabled".into(),
            name: "Enable Safe Attachments".into(),
            description: "Sandbox and scan email attachments before delivery".into(),
            category: "Defender for Office 365".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("2.1.4".into()),
            scuba_control: Some("MS.DEFENDER.2.1v1".into()),
        },
        TenantSetting {
            id: "safe_attachments_action".into(),
            name: "Safe Attachments Action".into(),
            description: "How to handle attachments during scanning".into(),
            category: "Defender for Office 365".into(),
            setting_type: SettingType::Choice {
                options: vec![
                    "Block".into(),
                    "Replace".into(),
                    "DynamicDelivery".into(),
                    "Monitor".into(),
                ],
            },
            default_value: SettingValue::String("DynamicDelivery".into()),
            current_value: None,
            recommended: true,
            cis_control: Some("2.1.4".into()),
            scuba_control: Some("MS.DEFENDER.2.2v1".into()),
        },
    ]
}

/// All Exchange Online settings
pub fn exchange_settings() -> Vec<TenantSetting> {
    vec![
        TenantSetting {
            id: "archive_mailbox".into(),
            name: "Enable Archive Mailboxes".into(),
            description: "Enable online archive for all user mailboxes".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: None,
        },
        TenantSetting {
            id: "auto_expanding_archive".into(),
            name: "Auto-Expanding Archive".into(),
            description: "Automatically expand archive storage beyond 100GB".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: None,
        },
        TenantSetting {
            id: "archive_after_years".into(),
            name: "Archive After (Years)".into(),
            description: "Move emails to archive after this many years".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Number {
                min: Some(1),
                max: Some(10),
            },
            default_value: SettingValue::Number(3),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: None,
        },
        TenantSetting {
            id: "quarantine_notifications".into(),
            name: "End-User Quarantine Notifications".into(),
            description: "Send email notifications when messages are quarantined".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(false),
            current_value: None,
            recommended: false,
            cis_control: None,
            scuba_control: None,
        },
        TenantSetting {
            id: "external_forwarding".into(),
            name: "Block External Auto-Forwarding".into(),
            description: "Prevent mailbox rules from forwarding to external addresses".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("6.2.1".into()),
            scuba_control: Some("MS.EXO.4.1v1".into()),
        },
        TenantSetting {
            id: "spam_bulk_threshold".into(),
            name: "Spam Bulk Threshold".into(),
            description: "Bulk email threshold (1-9, lower = more aggressive)".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Number {
                min: Some(1),
                max: Some(9),
            },
            default_value: SettingValue::Number(6),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: None,
        },
        TenantSetting {
            id: "high_confidence_spam_action".into(),
            name: "High Confidence Spam Action".into(),
            description: "Action for messages identified as definite spam".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Choice {
                options: vec![
                    "MoveToJmf".into(),
                    "Quarantine".into(),
                    "Delete".into(),
                    "Redirect".into(),
                ],
            },
            default_value: SettingValue::String("Quarantine".into()),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: Some("MS.EXO.3.1v1".into()),
        },
        TenantSetting {
            id: "phish_action".into(),
            name: "Phishing Email Action".into(),
            description: "Action for messages identified as phishing".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Choice {
                options: vec!["MoveToJmf".into(), "Quarantine".into(), "Delete".into()],
            },
            default_value: SettingValue::String("Quarantine".into()),
            current_value: None,
            recommended: true,
            cis_control: Some("4.2.1".into()),
            scuba_control: Some("MS.EXO.3.2v1".into()),
        },
        TenantSetting {
            id: "zap_enabled".into(),
            name: "Zero-Hour Auto Purge (ZAP)".into(),
            description: "Automatically remove delivered malicious messages".into(),
            category: "Exchange Online".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("4.3.1".into()),
            scuba_control: Some("MS.EXO.5.1v1".into()),
        },
    ]
}

/// All SharePoint/OneDrive settings
pub fn sharepoint_settings() -> Vec<TenantSetting> {
    vec![
        TenantSetting {
            id: "external_sharing".into(),
            name: "External Sharing Level".into(),
            description: "Control who can access shared content".into(),
            category: "SharePoint & OneDrive".into(),
            setting_type: SettingType::Choice {
                options: vec![
                    "Disabled".into(),
                    "ExistingExternalUserSharingOnly".into(),
                    "ExternalUserSharingOnly".into(),
                    "ExternalUserAndGuestSharing".into(),
                ],
            },
            default_value: SettingValue::String("ExistingExternalUserSharingOnly".into()),
            current_value: None,
            recommended: true,
            cis_control: Some("7.2.1".into()),
            scuba_control: Some("MS.SHAREPOINT.1.1v1".into()),
        },
        TenantSetting {
            id: "anonymous_link_expiry".into(),
            name: "Anonymous Link Expiry (Days)".into(),
            description: "Days before anonymous sharing links expire".into(),
            category: "SharePoint & OneDrive".into(),
            setting_type: SettingType::Number {
                min: Some(1),
                max: Some(365),
            },
            default_value: SettingValue::Number(30),
            current_value: None,
            recommended: true,
            cis_control: Some("7.2.3".into()),
            scuba_control: Some("MS.SHAREPOINT.1.3v1".into()),
        },
        TenantSetting {
            id: "default_sharing_link".into(),
            name: "Default Sharing Link Type".into(),
            description: "Default scope for new sharing links".into(),
            category: "SharePoint & OneDrive".into(),
            setting_type: SettingType::Choice {
                options: vec!["Internal".into(), "Direct".into(), "AnonymousAccess".into()],
            },
            default_value: SettingValue::String("Internal".into()),
            current_value: None,
            recommended: true,
            cis_control: Some("7.2.2".into()),
            scuba_control: Some("MS.SHAREPOINT.1.2v1".into()),
        },
        TenantSetting {
            id: "prevent_external_resharing".into(),
            name: "Prevent External Resharing".into(),
            description: "Prevent guests from re-sharing content".into(),
            category: "SharePoint & OneDrive".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("7.2.4".into()),
            scuba_control: None,
        },
        TenantSetting {
            id: "sync_client_restriction".into(),
            name: "Restrict OneDrive Sync to Managed Devices".into(),
            description: "Only allow OneDrive sync from domain-joined or compliant devices".into(),
            category: "SharePoint & OneDrive".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("7.3.1".into()),
            scuba_control: None,
        },
    ]
}

/// All Teams settings
pub fn teams_settings() -> Vec<TenantSetting> {
    vec![
        TenantSetting {
            id: "external_access".into(),
            name: "External Access (Federation)".into(),
            description: "Allow communication with external Teams/Skype users".into(),
            category: "Microsoft Teams".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: Some("8.1.1".into()),
            scuba_control: Some("MS.TEAMS.1.1v1".into()),
        },
        TenantSetting {
            id: "teams_consumer_access".into(),
            name: "Allow Personal Teams Accounts".into(),
            description: "Allow chat with personal Microsoft accounts".into(),
            category: "Microsoft Teams".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(false),
            current_value: None,
            recommended: false,
            cis_control: Some("8.1.2".into()),
            scuba_control: Some("MS.TEAMS.1.2v1".into()),
        },
        TenantSetting {
            id: "anonymous_meeting_join".into(),
            name: "Allow Anonymous Meeting Join".into(),
            description: "Allow unauthenticated users to join meetings".into(),
            category: "Microsoft Teams".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(false),
            current_value: None,
            recommended: false,
            cis_control: Some("8.2.1".into()),
            scuba_control: Some("MS.TEAMS.2.1v1".into()),
        },
        TenantSetting {
            id: "meeting_lobby".into(),
            name: "Auto-Admit Users".into(),
            description: "Who can bypass the meeting lobby".into(),
            category: "Microsoft Teams".into(),
            setting_type: SettingType::Choice {
                options: vec![
                    "EveryoneInCompany".into(),
                    "EveryoneInCompanyExcludingGuests".into(),
                    "OrganizerOnly".into(),
                    "InvitedUsers".into(),
                ],
            },
            default_value: SettingValue::String("EveryoneInCompanyExcludingGuests".into()),
            current_value: None,
            recommended: true,
            cis_control: Some("8.2.2".into()),
            scuba_control: Some("MS.TEAMS.2.2v1".into()),
        },
        TenantSetting {
            id: "meeting_recording".into(),
            name: "Allow Cloud Recording".into(),
            description: "Allow meeting recordings to be saved to cloud".into(),
            category: "Microsoft Teams".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: None,
        },
        TenantSetting {
            id: "meeting_transcription".into(),
            name: "Allow Transcription".into(),
            description: "Allow automatic meeting transcription".into(),
            category: "Microsoft Teams".into(),
            setting_type: SettingType::Boolean,
            default_value: SettingValue::Boolean(true),
            current_value: None,
            recommended: true,
            cis_control: None,
            scuba_control: None,
        },
    ]
}

/// Get all settings for a category
pub fn get_category_settings(category: SettingCategory) -> Vec<TenantSetting> {
    match category {
        SettingCategory::DefenderForOffice365 => defender_settings(),
        SettingCategory::ExchangeOnline => exchange_settings(),
        SettingCategory::SharePointOneDrive => sharepoint_settings(),
        SettingCategory::Teams => teams_settings(),
        SettingCategory::ConditionalAccess => vec![], // Handled separately via CA module
        SettingCategory::IntuneBaseline => vec![],    // Handled separately via baseline module
    }
}

/// Get all configurable settings
pub fn all_settings() -> Vec<TenantSetting> {
    let mut settings = Vec::new();
    settings.extend(defender_settings());
    settings.extend(exchange_settings());
    settings.extend(sharepoint_settings());
    settings.extend(teams_settings());
    settings
}

/// Collected settings from interactive session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantConfiguration {
    // Defender for Office 365
    pub safe_links_enabled: bool,
    pub safe_links_scan_urls: bool,
    pub safe_links_teams: bool,
    pub safe_links_office: bool,
    pub safe_links_track_clicks: bool,
    pub safe_links_internal_senders: bool,
    pub safe_attachments_enabled: bool,
    pub safe_attachments_action: String,

    // Exchange Online
    pub archive_mailbox: bool,
    pub auto_expanding_archive: bool,
    pub archive_after_years: u32,
    pub quarantine_notifications: bool,
    pub external_forwarding_blocked: bool,
    pub spam_bulk_threshold: u32,
    pub high_confidence_spam_action: String,
    pub phish_action: String,
    pub zap_enabled: bool,

    // SharePoint/OneDrive
    pub external_sharing: String,
    pub anonymous_link_expiry: u32,
    pub default_sharing_link: String,
    pub prevent_external_resharing: bool,
    pub sync_client_restriction: bool,

    // Teams
    pub external_access: bool,
    pub teams_consumer_access: bool,
    pub anonymous_meeting_join: bool,
    pub meeting_lobby: String,
    pub meeting_recording: bool,
    pub meeting_transcription: bool,
}

impl TenantConfiguration {
    pub fn recommended() -> Self {
        Self {
            // Defender - all enabled
            safe_links_enabled: true,
            safe_links_scan_urls: true,
            safe_links_teams: true,
            safe_links_office: true,
            safe_links_track_clicks: true,
            safe_links_internal_senders: true,
            safe_attachments_enabled: true,
            safe_attachments_action: "DynamicDelivery".into(),

            // Exchange - secure defaults
            archive_mailbox: true,
            auto_expanding_archive: true,
            archive_after_years: 3,
            quarantine_notifications: false,
            external_forwarding_blocked: true,
            spam_bulk_threshold: 6,
            high_confidence_spam_action: "Quarantine".into(),
            phish_action: "Quarantine".into(),
            zap_enabled: true,

            // SharePoint - restrictive
            external_sharing: "ExistingExternalUserSharingOnly".into(),
            anonymous_link_expiry: 30,
            default_sharing_link: "Internal".into(),
            prevent_external_resharing: true,
            sync_client_restriction: true,

            // Teams - balanced
            external_access: true,
            teams_consumer_access: false,
            anonymous_meeting_join: false,
            meeting_lobby: "EveryoneInCompanyExcludingGuests".into(),
            meeting_recording: true,
            meeting_transcription: true,
        }
    }
}
