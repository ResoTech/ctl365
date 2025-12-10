//! Conditional Access Baseline 2025
//!
//! 44 production-ready CA policies based on Kenneth van Surksum + Daniel Chronlund
//! <https://www.vansurksum.com/>
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

use serde_json::{Value, json};

pub struct CABaseline2025 {
    pub policies: Vec<CAPolicyTemplate>,
    pub groups: Vec<CAGroupTemplate>,
    pub named_locations: Vec<NamedLocationTemplate>,
}

/// A Conditional Access policy template with deployment metadata
#[derive(Debug, Clone)]
pub struct CAPolicyTemplate {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub state: String, // enabledForReportingButNotEnforced by default
    pub conditions: Value,
    pub grant_controls: Value,
    pub session_controls: Option<Value>,
    /// Impact level when enforced (Low, Medium, High, Critical)
    pub blast_radius: BlastRadius,
    /// Short summary for TUI display
    pub impact_summary: String,
}

impl Default for CAPolicyTemplate {
    fn default() -> Self {
        Self {
            id: String::new(),
            display_name: String::new(),
            description: String::new(),
            category: String::new(),
            state: "enabledForReportingButNotEnforced".to_string(),
            conditions: serde_json::json!({}),
            grant_controls: serde_json::json!({}),
            session_controls: None,
            blast_radius: BlastRadius::Medium, // Safe default
            impact_summary: "Review policy conditions before enabling.".to_string(),
        }
    }
}

/// Impact level for CA policy deployment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlastRadius {
    /// Affects few users/apps, low risk
    Low,
    /// Affects moderate number of users, some risk
    Medium,
    /// Affects many users or critical apps
    High,
    /// Affects all users, critical business impact potential
    Critical,
}

impl BlastRadius {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlastRadius::Low => "Low",
            BlastRadius::Medium => "Medium",
            BlastRadius::High => "High",
            BlastRadius::Critical => "Critical",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            BlastRadius::Low => "Minimal user impact, safe to enable",
            BlastRadius::Medium => "Moderate impact, review before enabling",
            BlastRadius::High => "High impact, thorough testing required",
            BlastRadius::Critical => "All users affected, careful validation essential",
        }
    }

    /// Determine blast radius from policy conditions
    pub fn from_conditions(conditions: &Value, category: &str) -> Self {
        // Check if affects all users
        let affects_all_users = conditions
            .get("users")
            .and_then(|u| u.get("includeUsers"))
            .and_then(|i| i.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some("All")))
            .unwrap_or(false);

        // Check if affects all applications
        let affects_all_apps = conditions
            .get("applications")
            .and_then(|a| a.get("includeApplications"))
            .and_then(|i| i.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some("All")))
            .unwrap_or(false);

        // Check if it's a blocking policy (vs grant/allow)
        let is_block_policy =
            category.contains("block") || category.to_lowercase().contains("block");

        // Determine blast radius
        match (affects_all_users, affects_all_apps, is_block_policy) {
            (true, true, true) => BlastRadius::Critical,
            (true, true, false) => BlastRadius::High,
            (true, false, _) => BlastRadius::High,
            (false, true, true) => BlastRadius::High,
            (false, true, false) => BlastRadius::Medium,
            (false, false, true) => BlastRadius::Medium,
            (false, false, false) => BlastRadius::Low,
        }
    }
}

impl CAPolicyTemplate {
    /// Create a new policy template with auto-calculated metadata
    pub fn new(
        id: &str,
        display_name: &str,
        description: &str,
        category: &str,
        conditions: Value,
        grant_controls: Value,
        session_controls: Option<Value>,
    ) -> Self {
        let blast_radius = BlastRadius::from_conditions(&conditions, category);
        let impact_summary = Self::generate_impact_summary(&conditions, category, &blast_radius);

        Self {
            id: id.to_string(),
            display_name: display_name.to_string(),
            description: description.to_string(),
            category: category.to_string(),
            state: "enabledForReportingButNotEnforced".to_string(),
            conditions,
            grant_controls,
            session_controls,
            blast_radius,
            impact_summary,
        }
    }

    fn generate_impact_summary(
        conditions: &Value,
        _category: &str,
        blast_radius: &BlastRadius,
    ) -> String {
        let user_target = conditions
            .get("users")
            .and_then(|u| u.get("includeUsers"))
            .and_then(|i| i.as_array())
            .map(|arr| {
                if arr.iter().any(|v| v.as_str() == Some("All")) {
                    "All users"
                } else if arr
                    .iter()
                    .any(|v| v.as_str().map(|s| s.contains("Admin")).unwrap_or(false))
                {
                    "Administrators"
                } else {
                    "Selected users"
                }
            })
            .unwrap_or("Unknown");

        let platform = conditions
            .get("platforms")
            .and_then(|p| p.get("includePlatforms"))
            .and_then(|i| i.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .unwrap_or("All platforms");

        format!(
            "{} impact on {} ({}). Mode: Report-Only by default.",
            blast_radius.as_str(),
            user_target,
            platform
        )
    }
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
                description: "Emergency break-glass accounts - excluded from all CA policies"
                    .to_string(),
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
            blast_radius: BlastRadius::High,
            impact_summary: "Requires device compliance for all macOS users. Ensure Intune enrollment is complete before enabling.".to_string(),
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
            blast_radius: BlastRadius::High,
            impact_summary: "Requires device compliance for all Windows users. Ensure Intune/SCCM enrollment is complete before enabling.".to_string(),
        }
    }

    // CAP001: Block legacy authentication
    fn cap001_block_legacy_auth() -> CAPolicyTemplate {
        CAPolicyTemplate {
            id: "CAP001".to_string(),
            display_name: "CAP001-All Block Legacy Authentication for All users when OtherClients"
                .to_string(),
            description: "Block legacy authentication protocols (IMAP, POP3, SMTP, etc.)"
                .to_string(),
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
            blast_radius: BlastRadius::Critical,
            impact_summary: "Blocks legacy auth for ALL users. Will break old Outlook, SMTP relay, IMAP/POP3 clients. Test thoroughly!".to_string(),
        }
    }

    // CAU001: Require MFA for all users
    fn cau001_require_mfa_all_users() -> CAPolicyTemplate {
        CAPolicyTemplate {
            id: "CAU001".to_string(),
            display_name: "CAU001-All Require MFA for All users".to_string(),
            description: "Require multi-factor authentication for all users accessing all apps"
                .to_string(),
            category: "User".to_string(),
            state: "enabledForReportingButNotEnforced".to_string(),
            blast_radius: BlastRadius::Critical,
            impact_summary: "MFA required for ALL users on ALL apps. Ensure all users have MFA registered before enabling.".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_all_policies() {
        let baseline = CABaseline2025::generate();
        // 15 CAD + 3 CAL + 4 CAP + 5 CAR + 8 CAS + 11 CAU = 46
        assert_eq!(baseline.policies.len(), 46);
    }

    #[test]
    fn test_policy_categories_represented() {
        let baseline = CABaseline2025::generate();

        let categories: Vec<&str> = baseline
            .policies
            .iter()
            .map(|p| p.category.as_str())
            .collect();

        assert!(categories.contains(&"Device"));
        assert!(categories.contains(&"Location"));
        assert!(categories.contains(&"Protocol"));
        assert!(categories.contains(&"Risk"));
        assert!(categories.contains(&"Service"));
        assert!(categories.contains(&"User"));
    }

    #[test]
    fn test_blast_radius_from_conditions_critical() {
        let conditions = json!({
            "users": { "includeUsers": ["All"] },
            "applications": { "includeApplications": ["All"] }
        });
        let radius = BlastRadius::from_conditions(&conditions, "block");
        assert_eq!(radius, BlastRadius::Critical);
    }

    #[test]
    fn test_blast_radius_from_conditions_high() {
        let conditions = json!({
            "users": { "includeUsers": ["All"] },
            "applications": { "includeApplications": ["Office365"] }
        });
        let radius = BlastRadius::from_conditions(&conditions, "grant");
        assert_eq!(radius, BlastRadius::High);
    }

    #[test]
    fn test_blast_radius_from_conditions_low() {
        let conditions = json!({
            "users": { "includeUsers": ["AdminGroup"] },
            "applications": { "includeApplications": ["SingleApp"] }
        });
        let radius = BlastRadius::from_conditions(&conditions, "grant");
        assert_eq!(radius, BlastRadius::Low);
    }

    #[test]
    fn test_blast_radius_as_str() {
        assert_eq!(BlastRadius::Low.as_str(), "Low");
        assert_eq!(BlastRadius::Medium.as_str(), "Medium");
        assert_eq!(BlastRadius::High.as_str(), "High");
        assert_eq!(BlastRadius::Critical.as_str(), "Critical");
    }

    #[test]
    fn test_blast_radius_description() {
        assert!(BlastRadius::Low.description().contains("safe"));
        assert!(BlastRadius::Critical.description().contains("All users"));
    }

    #[test]
    fn test_cap001_block_legacy_auth() {
        let baseline = CABaseline2025::generate();
        let policy = baseline.policies.iter().find(|p| p.id == "CAP001").unwrap();

        assert!(policy.display_name.contains("Legacy Authentication"));
        assert_eq!(policy.blast_radius, BlastRadius::Critical);
        assert!(policy.impact_summary.contains("Blocks legacy auth"));
    }

    #[test]
    fn test_cau001_require_mfa_all_users() {
        let baseline = CABaseline2025::generate();
        let policy = baseline.policies.iter().find(|p| p.id == "CAU001").unwrap();

        assert!(policy.display_name.contains("MFA"));
        assert_eq!(policy.blast_radius, BlastRadius::Critical);
        assert!(
            policy.conditions["users"]["includeUsers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some("All"))
        );
    }

    #[test]
    fn test_cad001_macos_compliant() {
        let baseline = CABaseline2025::generate();
        let policy = baseline.policies.iter().find(|p| p.id == "CAD001").unwrap();

        assert!(policy.display_name.contains("macOS"));
        assert_eq!(policy.category, "Device");
        assert_eq!(policy.state, "enabledForReportingButNotEnforced");
    }

    #[test]
    fn test_cad002_windows_compliant() {
        let baseline = CABaseline2025::generate();
        let policy = baseline.policies.iter().find(|p| p.id == "CAD002").unwrap();

        assert!(policy.display_name.contains("Windows"));
        assert_eq!(policy.category, "Device");
        assert!(
            policy.conditions["platforms"]["includePlatforms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some("windows"))
        );
    }

    #[test]
    fn test_all_policies_have_report_only_default() {
        let baseline = CABaseline2025::generate();
        for policy in &baseline.policies {
            assert_eq!(
                policy.state, "enabledForReportingButNotEnforced",
                "Policy {} should default to report-only",
                policy.id
            );
        }
    }

    #[test]
    fn test_all_policies_have_blast_radius() {
        let baseline = CABaseline2025::generate();
        for policy in &baseline.policies {
            // Just verify it's one of the valid enum values
            let _ = policy.blast_radius.as_str();
            assert!(!policy.impact_summary.is_empty());
        }
    }

    #[test]
    fn test_to_graph_json() {
        let baseline = CABaseline2025::generate();
        let policy = &baseline.policies[0];
        let json = CABaseline2025::to_graph_json(policy);

        assert_eq!(
            json["@odata.type"],
            "#microsoft.graph.conditionalAccessPolicy"
        );
        assert!(json["displayName"].is_string());
        assert!(json["state"].is_string());
        assert!(json["conditions"].is_object());
        assert!(json["grantControls"].is_object());
    }

    #[test]
    fn test_required_groups_generated() {
        let baseline = CABaseline2025::generate();
        assert!(!baseline.groups.is_empty());

        let breakglass = baseline.groups.iter().find(|g| g.purpose == "breakglass");
        assert!(breakglass.is_some());
    }

    #[test]
    fn test_named_locations_generated() {
        let baseline = CABaseline2025::generate();
        assert!(!baseline.named_locations.is_empty());

        let has_country_location = baseline
            .named_locations
            .iter()
            .any(|l| l.location_type == "country");
        assert!(has_country_location);
    }

    #[test]
    fn test_ca_policy_template_new() {
        let policy = CAPolicyTemplate::new(
            "TEST001",
            "Test Policy",
            "Test Description",
            "Test",
            json!({
                "users": { "includeUsers": ["All"] },
                "applications": { "includeApplications": ["All"] }
            }),
            json!({ "operator": "OR", "builtInControls": ["mfa"] }),
            None,
        );

        assert_eq!(policy.id, "TEST001");
        assert_eq!(policy.display_name, "Test Policy");
        // Auto-calculated blast radius should be High for all users + all apps (grant)
        // Critical requires block category
        assert_eq!(policy.blast_radius, BlastRadius::High);
        assert!(!policy.impact_summary.is_empty());
    }

    #[test]
    fn test_ca_policy_template_default() {
        let policy = CAPolicyTemplate::default();
        assert!(policy.id.is_empty());
        assert_eq!(policy.state, "enabledForReportingButNotEnforced");
        assert_eq!(policy.blast_radius, BlastRadius::Medium);
    }
}
