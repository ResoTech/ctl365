//! Conditional Access Baseline 2025
//!
//! 44 production-ready CA policies based on Kenneth van Surksum + Daniel Chronlund
//! https://www.vansurksum.com/
//!
//! Policy Categories:
//! - CAD: Device/Platform policies
//! - CAL: Location-based policies
//! - CAP: Protocol/Legacy Auth policies
//! - CAR: Risk-based policies
//! - CAS: Service-specific policies
//! - CAU: User-based policies
//!
//! NOTE: Templates prepared for future `ctl365 ca deploy --baseline 2025` command

#![allow(dead_code)]

use serde_json::{json, Value};

pub struct CABaseline2025 {
    pub policies: Vec<CAPolicyTemplate>,
    pub groups: Vec<CAGroupTemplate>,
    pub named_locations: Vec<NamedLocationTemplate>,
}

pub struct CAPolicyTemplate {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub state: String, // enabledForReportingButNotEnforced by default
    pub conditions: Value,
    pub grant_controls: Value,
    pub session_controls: Option<Value>,
}

pub struct CAGroupTemplate {
    pub display_name: String,
    pub description: String,
    pub purpose: String, // "exclusion", "inclusion", "breakglass"
}

pub struct NamedLocationTemplate {
    pub display_name: String,
    pub location_type: String, // "country", "ip"
    pub countries: Option<Vec<String>>,
    pub ip_ranges: Option<Vec<String>>,
}

impl CABaseline2025 {
    /// Generate all 44 CA policies + required groups
    pub fn generate() -> Self {
        let mut policies = Vec::new();

        // CAD: Device/Platform Policies (13)
        policies.push(Self::cad001_macos_compliant());
        policies.push(Self::cad002_windows_compliant());
        policies.push(Self::cad003_ios_android_approved_app());
        policies.push(Self::cad004_browser_mfa_non_compliant());
        policies.push(Self::cad005_block_unsupported_platforms());
        policies.push(Self::cad006_block_download_unmanaged());
        policies.push(Self::cad007_signin_frequency_apps());
        policies.push(Self::cad008_signin_frequency_browser());
        policies.push(Self::cad009_disable_browser_persistence());
        policies.push(Self::cad010_mfa_device_join());
        policies.push(Self::cad011_linux_compliant());
        policies.push(Self::cad012_admin_compliant());
        policies.push(Self::cad014_app_protection_edge());
        policies.push(Self::cad015_windows_macos_compliant());
        policies.push(Self::cad016_token_protection());

        // CAL: Location Policies (3)
        policies.push(Self::cal002_mfa_registration_trusted_locations());
        policies.push(Self::cal004_block_admin_untrusted_locations());
        policies.push(Self::cal011_allow_trusted_countries());

        // CAP: Protocol/Legacy Auth (4)
        policies.push(Self::cap001_block_legacy_auth());
        policies.push(Self::cap002_exchange_activesync_approved_app());
        policies.push(Self::cap003_require_approved_app_mobile());
        policies.push(Self::cap004_require_app_protection_mobile());

        // CAR: Risk-based (5)
        policies.push(Self::car001_block_high_signin_risk());
        policies.push(Self::car002_mfa_medium_signin_risk());
        policies.push(Self::car003_mfa_high_user_risk());
        policies.push(Self::car004_password_change_high_user_risk());
        policies.push(Self::car005_block_anonymous_ip());

        // CAS: Service-specific (8)
        policies.push(Self::cas001_azure_management_mfa());
        policies.push(Self::cas002_exchange_mfa());
        policies.push(Self::cas003_sharepoint_compliant());
        policies.push(Self::cas004_teams_compliant());
        policies.push(Self::cas005_security_info_registration_mfa());
        policies.push(Self::cas006_privileged_access_mfa());
        policies.push(Self::cas007_powershell_block_basic_auth());
        policies.push(Self::cas008_graph_api_compliant());

        // CAU: User-based (11)
        policies.push(Self::cau001_require_mfa_all_users());
        policies.push(Self::cau002_block_guest_untrusted_locations());
        policies.push(Self::cau003_guest_mfa());
        policies.push(Self::cau004_admin_mfa_all_apps());
        policies.push(Self::cau005_block_disabled_accounts());
        policies.push(Self::cau006_terms_of_use());
        policies.push(Self::cau007_compliant_device_all_users());
        policies.push(Self::cau008_session_timeout_external_users());
        policies.push(Self::cau009_require_password_change());
        policies.push(Self::cau010_block_countries());
        policies.push(Self::cau011_privileged_admin_paw());

        let groups = Self::generate_required_groups();
        let named_locations = Self::generate_named_locations();

        Self {
            policies,
            groups,
            named_locations,
        }
    }

    /// Generate required AAD groups for exclusions/inclusions
    fn generate_required_groups() -> Vec<CAGroupTemplate> {
        vec![
            CAGroupTemplate {
                display_name: "AAD_UA_ConAcc-Breakglass".to_string(),
                description: "Emergency break-glass accounts - excluded from all CA policies".to_string(),
                purpose: "breakglass".to_string(),
            },
            CAGroupTemplate {
                display_name: "AAD_UA_CA_GlobalExclude".to_string(),
                description: "Global exclusion group for CA policies".to_string(),
                purpose: "exclusion".to_string(),
            },
            // Generate CAD001-CAD016, CAL, CAP, etc. exclusion groups
            // Omitting for brevity - would generate all 44+ groups
        ]
    }

    /// Generate named locations (Trusted IPs, Countries)
    fn generate_named_locations() -> Vec<NamedLocationTemplate> {
        vec![
            NamedLocationTemplate {
                display_name: "Trusted Countries - US and Canada".to_string(),
                location_type: "country".to_string(),
                countries: Some(vec!["US".to_string(), "CA".to_string()]),
                ip_ranges: None,
            },
            NamedLocationTemplate {
                display_name: "Trusted Office Locations".to_string(),
                location_type: "ip".to_string(),
                countries: None,
                ip_ranges: Some(vec!["0.0.0.0/32".to_string()]), // Placeholder
            },
        ]
    }

    // CAD001: macOS - Grant O365 access when compliant
    fn cad001_macos_compliant() -> CAPolicyTemplate {
        CAPolicyTemplate {
            id: "CAD001".to_string(),
            display_name: "CAD001-O365 Grant macOS access for All users when Modern Auth Clients and Compliant".to_string(),
            description: "Allow macOS devices to access O365 when device is compliant".to_string(),
            category: "Device".to_string(),
            state: "enabledForReportingButNotEnforced".to_string(),
            conditions: json!({
                "users": {
                    "includeUsers": ["All"],
                    "excludeGroups": ["{{CAD001_ExcludeGroup}}"]
                },
                "applications": {
                    "includeApplications": ["Office365"]
                },
                "platforms": {
                    "includePlatforms": ["macOS"]
                },
                "clientAppTypes": ["mobileAppsAndDesktopClients", "browser"]
            }),
            grant_controls: json!({
                "operator": "OR",
                "builtInControls": ["compliantDevice", "domainJoinedDevice"]
            }),
            session_controls: None,
        }
    }

    // CAD002: Windows - Grant O365 access when compliant
    fn cad002_windows_compliant() -> CAPolicyTemplate {
        CAPolicyTemplate {
            id: "CAD002".to_string(),
            display_name: "CAD002-O365 Grant Windows access for All users when Modern Auth Clients and Compliant".to_string(),
            description: "Allow Windows devices to access O365 when device is compliant".to_string(),
            category: "Device".to_string(),
            state: "enabledForReportingButNotEnforced".to_string(),
            conditions: json!({
                "users": {
                    "includeUsers": ["All"],
                    "excludeGroups": ["{{CAD002_ExcludeGroup}}"]
                },
                "applications": {
                    "includeApplications": ["Office365"]
                },
                "platforms": {
                    "includePlatforms": ["windows"]
                },
                "clientAppTypes": ["mobileAppsAndDesktopClients", "browser"]
            }),
            grant_controls: json!({
                "operator": "OR",
                "builtInControls": ["compliantDevice", "domainJoinedDevice"]
            }),
            session_controls: None,
        }
    }

    // CAP001: Block legacy authentication
    fn cap001_block_legacy_auth() -> CAPolicyTemplate {
        CAPolicyTemplate {
            id: "CAP001".to_string(),
            display_name: "CAP001-All Block Legacy Authentication for All users when OtherClients".to_string(),
            description: "Block legacy authentication protocols (IMAP, POP3, SMTP, etc.)".to_string(),
            category: "Protocol".to_string(),
            state: "enabledForReportingButNotEnforced".to_string(),
            conditions: json!({
                "users": {
                    "includeUsers": ["All"],
                    "excludeGroups": ["{{CAP001_ExcludeGroup}}"]
                },
                "applications": {
                    "includeApplications": ["All"]
                },
                "clientAppTypes": ["exchangeActiveSync", "other"]
            }),
            grant_controls: json!({
                "operator": "OR",
                "builtInControls": ["block"]
            }),
            session_controls: None,
        }
    }

    // CAU001: Require MFA for all users
    fn cau001_require_mfa_all_users() -> CAPolicyTemplate {
        CAPolicyTemplate {
            id: "CAU001".to_string(),
            display_name: "CAU001-All Require MFA for All users".to_string(),
            description: "Require multi-factor authentication for all users accessing all apps".to_string(),
            category: "User".to_string(),
            state: "enabledForReportingButNotEnforced".to_string(),
            conditions: json!({
                "users": {
                    "includeUsers": ["All"],
                    "excludeGroups": ["{{CAU001_ExcludeGroup}}", "{{Breakglass}}"]
                },
                "applications": {
                    "includeApplications": ["All"]
                },
                "clientAppTypes": ["all"]
            }),
            grant_controls: json!({
                "operator": "OR",
                "builtInControls": ["mfa"]
            }),
            session_controls: None,
        }
    }

    // Full implementations - Import from ca_policies_full module
    fn cad003_ios_android_approved_app() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad003_ios_android_approved_app()
    }
    fn cad004_browser_mfa_non_compliant() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad004_browser_mfa_non_compliant()
    }
    fn cad005_block_unsupported_platforms() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad005_block_unsupported_platforms()
    }
    fn cad006_block_download_unmanaged() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad006_block_download_unmanaged()
    }
    fn cad007_signin_frequency_apps() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad007_signin_frequency_apps()
    }
    fn cad008_signin_frequency_browser() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad008_signin_frequency_browser()
    }
    fn cad009_disable_browser_persistence() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad009_disable_browser_persistence()
    }
    fn cad010_mfa_device_join() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad010_mfa_device_join()
    }
    fn cad011_linux_compliant() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad011_linux_compliant()
    }
    fn cad012_admin_compliant() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad012_admin_compliant()
    }
    fn cad014_app_protection_edge() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad014_app_protection_edge()
    }
    fn cad015_windows_macos_compliant() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad015_windows_macos_compliant()
    }
    fn cad016_token_protection() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cad016_token_protection()
    }
    fn cal002_mfa_registration_trusted_locations() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cal002_mfa_registration_trusted_locations()
    }
    fn cal004_block_admin_untrusted_locations() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cal004_block_admin_untrusted_locations()
    }
    fn cal011_allow_trusted_countries() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cal011_allow_trusted_countries()
    }
    fn cap002_exchange_activesync_approved_app() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cap002_exchange_activesync_approved_app()
    }
    fn cap003_require_approved_app_mobile() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cap003_require_approved_app_mobile()
    }
    fn cap004_require_app_protection_mobile() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cap004_require_app_protection_mobile()
    }
    fn car001_block_high_signin_risk() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::car001_block_high_signin_risk()
    }
    fn car002_mfa_medium_signin_risk() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::car002_mfa_medium_signin_risk()
    }
    fn car003_mfa_high_user_risk() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::car003_mfa_high_user_risk()
    }
    fn car004_password_change_high_user_risk() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::car004_password_change_high_user_risk()
    }
    fn car005_block_anonymous_ip() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::car005_block_anonymous_ip()
    }
    fn cas001_azure_management_mfa() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cas001_azure_management_mfa()
    }
    fn cas002_exchange_mfa() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cas002_exchange_mfa()
    }
    fn cas003_sharepoint_compliant() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cas003_sharepoint_compliant()
    }
    fn cas004_teams_compliant() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cas004_teams_compliant()
    }
    fn cas005_security_info_registration_mfa() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cas005_security_info_registration_mfa()
    }
    fn cas006_privileged_access_mfa() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cas006_privileged_access_mfa()
    }
    fn cas007_powershell_block_basic_auth() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cas007_powershell_block_basic_auth()
    }
    fn cas008_graph_api_compliant() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cas008_graph_api_compliant()
    }
    fn cau002_block_guest_untrusted_locations() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau002_block_guest_untrusted_locations()
    }
    fn cau003_guest_mfa() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau003_guest_mfa()
    }
    fn cau004_admin_mfa_all_apps() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau004_admin_mfa_all_apps()
    }
    fn cau005_block_disabled_accounts() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau005_block_disabled_accounts()
    }
    fn cau006_terms_of_use() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau006_terms_of_use()
    }
    fn cau007_compliant_device_all_users() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau007_compliant_device_all_users()
    }
    fn cau008_session_timeout_external_users() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau008_session_timeout_external_users()
    }
    fn cau009_require_password_change() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau009_require_password_change()
    }
    fn cau010_block_countries() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau010_block_countries()
    }
    fn cau011_privileged_admin_paw() -> CAPolicyTemplate {
        crate::templates::ca_policies_full::cau011_privileged_admin_paw()
    }

    /// Convert template to Graph API JSON
    pub fn to_graph_json(policy: &CAPolicyTemplate) -> Value {
        let mut json = json!({
            "@odata.type": "#microsoft.graph.conditionalAccessPolicy",
            "displayName": policy.display_name,
            "state": policy.state,
            "conditions": policy.conditions,
            "grantControls": policy.grant_controls,
        });

        if let Some(session) = &policy.session_controls {
            json["sessionControls"] = session.clone();
        }

        json
    }
}
