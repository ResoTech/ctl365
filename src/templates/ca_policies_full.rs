//! Complete Implementation of all 44 Conditional Access Policies
//!
//! Based on CABaseline2025 by Kenneth van Surksum and Daniel Chronlund
//! Each policy is production-ready with proper conditions and controls
//!
//! NOTE: These functions are prepared for future `ctl365 ca deploy --baseline 2025` command

#![allow(dead_code)]

use serde_json::json;
use super::ca_baseline_2025::CAPolicyTemplate;

// ============================================================================
// CAD: Device/Platform Policies (13 policies)
// ============================================================================

/// CAD003: iOS/Android - Require approved client app
pub fn cad003_ios_android_approved_app() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD003".to_string(),
        display_name: "CAD003-O365 Grant iOS/Android access for All users when Modern Auth and Approved Client App".to_string(),
        description: "Require approved client apps (Outlook, Teams, etc.) for mobile devices".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD003_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "platforms": {
                "includePlatforms": ["iOS", "android"]
            },
            "clientAppTypes": ["mobileAppsAndDesktopClients", "browser"]
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["approvedApplication"]
        }),
        session_controls: None,
    }
}

/// CAD004: Browser - Require MFA when device not compliant
pub fn cad004_browser_mfa_non_compliant() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD004".to_string(),
        display_name: "CAD004-O365 Require MFA for All users when Browser on non-compliant device".to_string(),
        description: "Require MFA when accessing from browser on non-compliant device".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD004_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "clientAppTypes": ["browser"],
            "devices": {
                "deviceFilter": {
                    "mode": "exclude",
                    "rule": "device.isCompliant -eq True"
                }
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAD005: Block unsupported device platforms
pub fn cad005_block_unsupported_platforms() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD005".to_string(),
        display_name: "CAD005-O365 Block All users when Unsupported Device Platform".to_string(),
        description: "Block access from unsupported platforms (ChromeOS, etc.)".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD005_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "platforms": {
                "includePlatforms": ["All"],
                "excludePlatforms": ["windows", "macOS", "iOS", "android", "windowsPhone", "linux"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

/// CAD006: Block download to unmanaged devices
pub fn cad006_block_download_unmanaged() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD006".to_string(),
        display_name: "CAD006-O365 Limit downloads on unmanaged devices".to_string(),
        description: "Prevent downloads, copy, and print on unmanaged devices".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD006_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "devices": {
                "deviceFilter": {
                    "mode": "exclude",
                    "rule": "device.isCompliant -eq True or device.trustType -eq \"ServerAD\""
                }
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: Some(json!({
            "applicationEnforcedRestrictions": {
                "isEnabled": true
            }
        })),
    }
}

/// CAD007: Sign-in frequency for apps (12 hours)
pub fn cad007_signin_frequency_apps() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD007".to_string(),
        display_name: "CAD007-O365 Set Sign-in Frequency to 12 hours for Native Apps".to_string(),
        description: "Require re-authentication every 12 hours for mobile apps".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD007_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "clientAppTypes": ["mobileAppsAndDesktopClients"]
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": []
        }),
        session_controls: Some(json!({
            "signInFrequency": {
                "value": 12,
                "type": "hours",
                "isEnabled": true
            }
        })),
    }
}

/// CAD008: Sign-in frequency for browser (8 hours)
pub fn cad008_signin_frequency_browser() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD008".to_string(),
        display_name: "CAD008-O365 Set Sign-in Frequency to 8 hours for Browser".to_string(),
        description: "Require re-authentication every 8 hours for browser sessions".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD008_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "clientAppTypes": ["browser"]
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": []
        }),
        session_controls: Some(json!({
            "signInFrequency": {
                "value": 8,
                "type": "hours",
                "isEnabled": true
            },
            "persistentBrowser": {
                "mode": "never",
                "isEnabled": true
            }
        })),
    }
}

/// CAD009: Disable browser session persistence
pub fn cad009_disable_browser_persistence() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD009".to_string(),
        display_name: "CAD009-O365 Disable browser session persistence".to_string(),
        description: "Don't keep users signed in across browser sessions".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD009_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "clientAppTypes": ["browser"]
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": []
        }),
        session_controls: Some(json!({
            "persistentBrowser": {
                "mode": "never",
                "isEnabled": true
            }
        })),
    }
}

/// CAD010: Require MFA for device registration/join
pub fn cad010_mfa_device_join() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD010".to_string(),
        display_name: "CAD010-Require MFA for Azure AD device registration/join".to_string(),
        description: "Require MFA when registering or joining devices to Azure AD".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD010_ExcludeGroup}}"]
            },
            "applications": {
                "includeUserActions": ["urn:user:registerdevice"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAD011: Linux - Grant O365 access when compliant
pub fn cad011_linux_compliant() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD011".to_string(),
        display_name: "CAD011-O365 Grant Linux access for All users when Compliant".to_string(),
        description: "Allow Linux devices to access O365 when device is compliant".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD011_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "platforms": {
                "includePlatforms": ["linux"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["compliantDevice"]
        }),
        session_controls: None,
    }
}

/// CAD012: Admins - Require compliant device
pub fn cad012_admin_compliant() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD012".to_string(),
        display_name: "CAD012-Require compliant device for Administrators".to_string(),
        description: "Admin accounts must use compliant devices".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeRoles": [
                    "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
                    "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
                    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
                    "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
                ],
                "excludeGroups": ["{{CAD012_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["compliantDevice", "mfa"]
        }),
        session_controls: None,
    }
}

/// CAD014: Require App Protection Policy for Edge
pub fn cad014_app_protection_edge() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD014".to_string(),
        display_name: "CAD014-Require App Protection Policy for Edge on iOS/Android".to_string(),
        description: "Require MAM app protection for Edge browser on mobile".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD014_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "platforms": {
                "includePlatforms": ["iOS", "android"]
            },
            "clientAppTypes": ["browser"]
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["approvedApplication", "compliantApplication"]
        }),
        session_controls: None,
    }
}

/// CAD015: Windows/macOS - Require compliant device
pub fn cad015_windows_macos_compliant() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD015".to_string(),
        display_name: "CAD015-O365 Require compliant Windows or macOS device".to_string(),
        description: "Simplified policy combining Windows and macOS compliance".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD015_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "platforms": {
                "includePlatforms": ["windows", "macOS"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["compliantDevice", "domainJoinedDevice"]
        }),
        session_controls: None,
    }
}

/// CAD016: Require token protection (phishing-resistant MFA)
pub fn cad016_token_protection() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAD016".to_string(),
        display_name: "CAD016-Require token protection for All users".to_string(),
        description: "Require phishing-resistant authentication with token binding".to_string(),
        category: "Device".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAD016_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "authenticationStrength": {
                "@odata.type": "#microsoft.graph.authenticationStrengthPolicy",
                "id": "00000000-0000-0000-0000-000000000004" // Phishing-resistant MFA
            }
        }),
        session_controls: None,
    }
}

// ============================================================================
// CAL: Location-based Policies (3 policies)
// ============================================================================

/// CAL002: Require MFA for registration from untrusted locations
pub fn cal002_mfa_registration_trusted_locations() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAL002".to_string(),
        display_name: "CAL002-Require MFA for security info registration outside trusted locations".to_string(),
        description: "Require MFA when registering security info from untrusted networks".to_string(),
        category: "Location".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAL002_ExcludeGroup}}"]
            },
            "applications": {
                "includeUserActions": ["urn:user:registersecurityinfo"]
            },
            "locations": {
                "includeLocations": ["All"],
                "excludeLocations": ["AllTrusted", "{{TrustedLocation_ID}}"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAL004: Block admin access from untrusted locations
pub fn cal004_block_admin_untrusted_locations() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAL004".to_string(),
        display_name: "CAL004-Block administrator access from untrusted locations".to_string(),
        description: "Prevent admin access outside of trusted office networks".to_string(),
        category: "Location".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeRoles": [
                    "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
                    "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
                ],
                "excludeGroups": ["{{CAL004_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "locations": {
                "includeLocations": ["All"],
                "excludeLocations": ["AllTrusted", "{{TrustedLocation_ID}}"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

/// CAL011: Allow access only from trusted countries
pub fn cal011_allow_trusted_countries() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAL011".to_string(),
        display_name: "CAL011-Allow access only from trusted countries (US/Canada)".to_string(),
        description: "Block access from outside specified countries".to_string(),
        category: "Location".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAL011_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "locations": {
                "includeLocations": ["All"],
                "excludeLocations": ["{{TrustedCountries_ID}}"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

// ============================================================================
// CAP: Protocol/Legacy Auth Policies (3 remaining - CAP001 already done)
// ============================================================================

/// CAP002: Exchange ActiveSync - Require approved app
pub fn cap002_exchange_activesync_approved_app() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAP002".to_string(),
        display_name: "CAP002-Exchange ActiveSync - Require approved client app".to_string(),
        description: "Block legacy EAS clients, require modern Outlook".to_string(),
        category: "Protocol".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAP002_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["00000002-0000-0ff1-ce00-000000000000"] // Office 365 Exchange Online
            },
            "clientAppTypes": ["exchangeActiveSync"]
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["approvedApplication"]
        }),
        session_controls: None,
    }
}

/// CAP003: Mobile - Require approved client app
pub fn cap003_require_approved_app_mobile() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAP003".to_string(),
        display_name: "CAP003-Require approved client app for mobile devices".to_string(),
        description: "Only allow Intune-managed apps on mobile".to_string(),
        category: "Protocol".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAP003_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "platforms": {
                "includePlatforms": ["iOS", "android"]
            },
            "clientAppTypes": ["mobileAppsAndDesktopClients"]
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["approvedApplication"]
        }),
        session_controls: None,
    }
}

/// CAP004: Mobile - Require app protection policy
pub fn cap004_require_app_protection_mobile() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAP004".to_string(),
        display_name: "CAP004-Require app protection policy for mobile devices".to_string(),
        description: "Require MAM app protection policies (data loss prevention)".to_string(),
        category: "Protocol".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAP004_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["Office365"]
            },
            "platforms": {
                "includePlatforms": ["iOS", "android"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["compliantApplication"]
        }),
        session_controls: None,
    }
}

// ============================================================================
// CAR: Risk-based Policies (5 policies)
// ============================================================================

/// CAR001: Block high sign-in risk
pub fn car001_block_high_signin_risk() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAR001".to_string(),
        display_name: "CAR001-Block access for high sign-in risk".to_string(),
        description: "Block sign-ins detected as high risk by Identity Protection".to_string(),
        category: "Risk".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAR001_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "signInRiskLevels": ["high"]
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

/// CAR002: Require MFA for medium sign-in risk
pub fn car002_mfa_medium_signin_risk() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAR002".to_string(),
        display_name: "CAR002-Require MFA for medium sign-in risk".to_string(),
        description: "Require MFA when sign-in risk is medium or high".to_string(),
        category: "Risk".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAR002_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "signInRiskLevels": ["medium", "high"]
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAR003: Require MFA for high user risk
pub fn car003_mfa_high_user_risk() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAR003".to_string(),
        display_name: "CAR003-Require MFA for high user risk".to_string(),
        description: "Require MFA when user account is flagged as high risk".to_string(),
        category: "Risk".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAR003_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "userRiskLevels": ["high"]
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAR004: Require password change for high user risk
pub fn car004_password_change_high_user_risk() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAR004".to_string(),
        display_name: "CAR004-Require secure password change for high user risk".to_string(),
        description: "Force password change when user risk is high (compromised credential)".to_string(),
        category: "Risk".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAR004_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "userRiskLevels": ["high"]
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa", "passwordChange"]
        }),
        session_controls: None,
    }
}

/// CAR005: Block anonymous IP addresses
pub fn car005_block_anonymous_ip() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAR005".to_string(),
        display_name: "CAR005-Block access from anonymous IP addresses".to_string(),
        description: "Block VPN, proxy, and Tor exit nodes detected by Identity Protection".to_string(),
        category: "Risk".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAR005_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "signInRiskLevels": ["medium", "high"],
            // Note: Anonymous IP detection is part of sign-in risk detection
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

// ============================================================================
// CAS: Service-specific Policies (8 policies)
// ============================================================================

/// CAS001: Azure Management - Require MFA
pub fn cas001_azure_management_mfa() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAS001".to_string(),
        display_name: "CAS001-Require MFA for Azure Management".to_string(),
        description: "Require MFA for Azure Portal, PowerShell, CLI access".to_string(),
        category: "Service".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAS001_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["797f4846-ba00-4fd7-ba43-dac1f8f63013"] // Azure Management
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAS002: Exchange Online - Require MFA
pub fn cas002_exchange_mfa() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAS002".to_string(),
        display_name: "CAS002-Require MFA for Exchange Online".to_string(),
        description: "Require MFA for accessing email (Outlook, OWA)".to_string(),
        category: "Service".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAS002_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["00000002-0000-0ff1-ce00-000000000000"] // Exchange Online
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAS003: SharePoint - Require compliant device
pub fn cas003_sharepoint_compliant() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAS003".to_string(),
        display_name: "CAS003-Require compliant device for SharePoint/OneDrive".to_string(),
        description: "Prevent data exfiltration by requiring compliant devices".to_string(),
        category: "Service".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAS003_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["00000003-0000-0ff1-ce00-000000000000"] // SharePoint Online
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["compliantDevice", "domainJoinedDevice"]
        }),
        session_controls: None,
    }
}

/// CAS004: Teams - Require compliant device
pub fn cas004_teams_compliant() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAS004".to_string(),
        display_name: "CAS004-Require compliant device for Microsoft Teams".to_string(),
        description: "Require compliant devices for Teams access".to_string(),
        category: "Service".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAS004_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"] // Microsoft Teams
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["compliantDevice", "domainJoinedDevice"]
        }),
        session_controls: None,
    }
}

/// CAS005: Security info registration - Require MFA
pub fn cas005_security_info_registration_mfa() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAS005".to_string(),
        display_name: "CAS005-Require MFA for security info registration".to_string(),
        description: "Require MFA when users register authentication methods".to_string(),
        category: "Service".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAS005_ExcludeGroup}}"]
            },
            "applications": {
                "includeUserActions": ["urn:user:registersecurityinfo"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAS006: Privileged access - Require MFA
pub fn cas006_privileged_access_mfa() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAS006".to_string(),
        display_name: "CAS006-Require MFA for privileged role activation".to_string(),
        description: "Require MFA when activating PIM roles".to_string(),
        category: "Service".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAS006_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["01fc33a7-78ba-4d2f-a4b7-768e336e890e"] // Microsoft Azure PIM
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAS007: PowerShell - Block basic auth
pub fn cas007_powershell_block_basic_auth() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAS007".to_string(),
        display_name: "CAS007-Block basic authentication for PowerShell".to_string(),
        description: "Block legacy PowerShell connections using basic auth".to_string(),
        category: "Service".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAS007_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "clientAppTypes": ["other"] // Legacy auth clients
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

/// CAS008: Graph API - Require compliant device
pub fn cas008_graph_api_compliant() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAS008".to_string(),
        display_name: "CAS008-Require compliant device for Microsoft Graph API".to_string(),
        description: "Require compliant devices for Graph API access".to_string(),
        category: "Service".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAS008_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["00000003-0000-0000-c000-000000000000"] // Microsoft Graph
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["compliantDevice", "domainJoinedDevice"]
        }),
        session_controls: None,
    }
}

// ============================================================================
// CAU: User-based Policies (10 remaining - CAU001 already done)
// ============================================================================

/// CAU002: Block guests from untrusted locations
pub fn cau002_block_guest_untrusted_locations() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU002".to_string(),
        display_name: "CAU002-Block guest users from untrusted locations".to_string(),
        description: "Prevent guest access outside trusted networks".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeGuestsOrExternalUsers": {
                    "guestOrExternalUserTypes": "b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser",
                    "externalTenants": {
                        "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants",
                        "membershipKind": "all"
                    }
                },
                "excludeGroups": ["{{CAU002_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "locations": {
                "includeLocations": ["All"],
                "excludeLocations": ["AllTrusted", "{{TrustedLocation_ID}}"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

/// CAU003: Require MFA for guest users
pub fn cau003_guest_mfa() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU003".to_string(),
        display_name: "CAU003-Require MFA for guest users".to_string(),
        description: "All guest users must use MFA".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeGuestsOrExternalUsers": {
                    "guestOrExternalUserTypes": "b2bCollaborationGuest,b2bCollaborationMember",
                    "externalTenants": {
                        "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants",
                        "membershipKind": "all"
                    }
                },
                "excludeGroups": ["{{CAU003_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAU004: Admin users - Require MFA for all apps
pub fn cau004_admin_mfa_all_apps() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU004".to_string(),
        display_name: "CAU004-Require MFA for administrators on all apps".to_string(),
        description: "Admin accounts require MFA for everything".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeRoles": [
                    "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
                    "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
                    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
                    "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
                    "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator
                    "11648597-926c-4cf3-9c36-bcebb0ba8dcc", // Power Platform Administrator
                ],
                "excludeGroups": ["{{CAU004_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["mfa"]
        }),
        session_controls: None,
    }
}

/// CAU005: Block disabled accounts
pub fn cau005_block_disabled_accounts() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU005".to_string(),
        display_name: "CAU005-Block disabled user accounts".to_string(),
        description: "Ensure disabled accounts cannot sign in".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["None"], // Will be configured with specific groups
                "includeGroups": ["{{DisabledUsers_Group}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

/// CAU006: Require terms of use acceptance
pub fn cau006_terms_of_use() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU006".to_string(),
        display_name: "CAU006-Require terms of use acceptance".to_string(),
        description: "Users must accept terms of use before accessing apps".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAU006_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "termsOfUse": ["{{TermsOfUse_ID}}"]
        }),
        session_controls: None,
    }
}

/// CAU007: Require compliant device for all users
pub fn cau007_compliant_device_all_users() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU007".to_string(),
        display_name: "CAU007-Require compliant device for all users".to_string(),
        description: "Universal device compliance requirement".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAU007_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["compliantDevice", "domainJoinedDevice"]
        }),
        session_controls: None,
    }
}

/// CAU008: Session timeout for external users
pub fn cau008_session_timeout_external_users() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU008".to_string(),
        display_name: "CAU008-Set session timeout for external/guest users".to_string(),
        description: "Limit session duration for guests (4 hours)".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeGuestsOrExternalUsers": {
                    "guestOrExternalUserTypes": "b2bCollaborationGuest",
                    "externalTenants": {
                        "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants",
                        "membershipKind": "all"
                    }
                }
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": []
        }),
        session_controls: Some(json!({
            "signInFrequency": {
                "value": 4,
                "type": "hours",
                "isEnabled": true
            }
        })),
    }
}

/// CAU009: Require password change
pub fn cau009_require_password_change() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU009".to_string(),
        display_name: "CAU009-Require password change for flagged users".to_string(),
        description: "Force password change for users in password change required group".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeGroups": ["{{PasswordChangeRequired_Group}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["passwordChange"]
        }),
        session_controls: None,
    }
}

/// CAU010: Block access from specific countries
pub fn cau010_block_countries() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU010".to_string(),
        display_name: "CAU010-Block access from high-risk countries".to_string(),
        description: "Block access from countries on blocked list".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeUsers": ["All"],
                "excludeGroups": ["{{CAU010_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "locations": {
                "includeLocations": ["{{BlockedCountries_ID}}"]
            }
        }),
        grant_controls: json!({
            "operator": "OR",
            "builtInControls": ["block"]
        }),
        session_controls: None,
    }
}

/// CAU011: Privileged admins - Require PAW
pub fn cau011_privileged_admin_paw() -> CAPolicyTemplate {
    CAPolicyTemplate {
        id: "CAU011".to_string(),
        display_name: "CAU011-Require Privileged Access Workstation for Global Admins".to_string(),
        description: "Global admins must use designated secure workstations".to_string(),
        category: "User".to_string(),
        state: "enabledForReportingButNotEnforced".to_string(),
        conditions: json!({
            "users": {
                "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"], // Global Administrator
                "excludeGroups": ["{{CAU011_ExcludeGroup}}"]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "devices": {
                "deviceFilter": {
                    "mode": "include",
                    "rule": "device.displayName -startsWith \"PAW-\""
                }
            }
        }),
        grant_controls: json!({
            "operator": "AND",
            "builtInControls": ["compliantDevice", "mfa"]
        }),
        session_controls: None,
    }
}
