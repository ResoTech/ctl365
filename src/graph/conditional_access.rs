//! Conditional Access policy management via Microsoft Graph API
//!
//! Implements Zero Trust security patterns for Entra ID Conditional Access

#![allow(dead_code)]

use crate::error::Result;
use crate::graph::GraphClient;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Conditional Access Policy structure for typed responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalAccessPolicy {
    pub id: String,
    pub display_name: String,
    pub state: String,
    #[serde(default)]
    pub created_date_time: Option<String>,
    #[serde(default)]
    pub modified_date_time: Option<String>,
    #[serde(default)]
    pub conditions: Option<PolicyConditions>,
    #[serde(default)]
    pub grant_controls: Option<GrantControls>,
    #[serde(default)]
    pub session_controls: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConditions {
    #[serde(default)]
    pub users: Option<UserCondition>,
    #[serde(default)]
    pub applications: Option<ApplicationCondition>,
    #[serde(default)]
    pub locations: Option<LocationCondition>,
    #[serde(default)]
    pub platforms: Option<PlatformCondition>,
    #[serde(default)]
    pub client_app_types: Option<Vec<String>>,
    #[serde(default)]
    pub sign_in_risk_levels: Option<Vec<String>>,
    #[serde(default)]
    pub user_risk_levels: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCondition {
    #[serde(default)]
    pub include_users: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_users: Option<Vec<String>>,
    #[serde(default)]
    pub include_groups: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_groups: Option<Vec<String>>,
    #[serde(default)]
    pub include_roles: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_roles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationCondition {
    #[serde(default)]
    pub include_applications: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_applications: Option<Vec<String>>,
    #[serde(default)]
    pub include_user_actions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationCondition {
    #[serde(default)]
    pub include_locations: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_locations: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCondition {
    #[serde(default)]
    pub include_platforms: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_platforms: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantControls {
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub built_in_controls: Option<Vec<String>>,
    #[serde(default)]
    pub custom_authentication_factors: Option<Vec<String>>,
    #[serde(default)]
    pub terms_of_use: Option<Vec<String>>,
}

/// Named Location structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamedLocation {
    pub id: String,
    pub display_name: String,
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    #[serde(default)]
    pub is_trusted: Option<bool>,
    #[serde(default)]
    pub countries_and_regions: Option<Vec<String>>,
    #[serde(default)]
    pub ip_ranges: Option<Vec<IpRange>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpRange {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    pub cidr_address: String,
}

/// Create a Conditional Access policy
pub async fn create_policy(client: &GraphClient, policy: &Value) -> Result<Value> {
    client
        .post("identity/conditionalAccess/policies", policy)
        .await
}

/// List all Conditional Access policies with pagination support
pub async fn list_policies(client: &GraphClient) -> Result<Value> {
    // Use pagination to get ALL policies (not just first page)
    let policies: Vec<ConditionalAccessPolicy> = client
        .get_all_pages("identity/conditionalAccess/policies")
        .await?;
    
    // Convert back to Value format for backward compatibility
    Ok(json!({
        "value": policies,
        "@odata.count": policies.len()
    }))
}

/// List all CA policies as typed structs (preferred for new code)
pub async fn list_policies_typed(client: &GraphClient) -> Result<Vec<ConditionalAccessPolicy>> {
    client
        .get_all_pages("identity/conditionalAccess/policies")
        .await
}

/// List Named Locations with pagination support
pub async fn list_named_locations_typed(client: &GraphClient) -> Result<Vec<NamedLocation>> {
    client
        .get_all_pages("identity/conditionalAccess/namedLocations")
        .await
}

/// Get a specific CA policy by ID
pub async fn get_policy(client: &GraphClient, policy_id: &str) -> Result<Value> {
    client
        .get(&format!(
            "identity/conditionalAccess/policies/{}",
            policy_id
        ))
        .await
}

/// Get a specific CA policy by ID (typed)
pub async fn get_policy_typed(client: &GraphClient, policy_id: &str) -> Result<ConditionalAccessPolicy> {
    client
        .get(&format!(
            "identity/conditionalAccess/policies/{}",
            policy_id
        ))
        .await
}

/// Update a CA policy
pub async fn update_policy(client: &GraphClient, policy_id: &str, policy: &Value) -> Result<Value> {
    client
        .patch(
            &format!("identity/conditionalAccess/policies/{}", policy_id),
            policy,
        )
        .await
}

/// Delete a CA policy
pub async fn delete_policy(client: &GraphClient, policy_id: &str) -> Result<()> {
    client
        .delete(&format!(
            "identity/conditionalAccess/policies/{}",
            policy_id
        ))
        .await?;
    Ok(())
}

/// Create a Named Location (for GeoIP blocking)
pub async fn create_named_location(client: &GraphClient, location: &Value) -> Result<Value> {
    client
        .post("identity/conditionalAccess/namedLocations", location)
        .await
}

/// List Named Locations with pagination
pub async fn list_named_locations(client: &GraphClient) -> Result<Value> {
    let locations: Vec<NamedLocation> = client
        .get_all_pages("identity/conditionalAccess/namedLocations")
        .await?;
    
    Ok(json!({
        "value": locations,
        "@odata.count": locations.len()
    }))
}

/// Check if a named location with the given name already exists
pub async fn find_named_location_by_name(client: &GraphClient, name: &str) -> Result<Option<NamedLocation>> {
    let locations = list_named_locations_typed(client).await?;
    Ok(locations.into_iter().find(|loc| loc.display_name.eq_ignore_ascii_case(name)))
}

/// Check if a CA policy with the given name already exists
pub async fn find_policy_by_name(client: &GraphClient, name: &str) -> Result<Option<ConditionalAccessPolicy>> {
    let policies = list_policies_typed(client).await?;
    Ok(policies.into_iter().find(|p| p.display_name.eq_ignore_ascii_case(name)))
}

/// Get security defaults status
pub async fn get_security_defaults(client: &GraphClient) -> Result<Value> {
    client
        .get("policies/identitySecurityDefaultsEnforcementPolicy")
        .await
}

/// Disable security defaults (required before CA policies can be enforced)
pub async fn disable_security_defaults(client: &GraphClient) -> Result<Value> {
    let payload = json!({
        "isEnabled": false
    });

    client
        .patch(
            "policies/identitySecurityDefaultsEnforcementPolicy",
            &payload,
        )
        .await
}

/// Generate MFA enforcement policy (Require MFA for all users)
pub fn generate_mfa_policy(name: &str, exclude_group_ids: Vec<String>) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.conditionalAccessPolicy",
        "displayName": name,
        "state": "enabledForReportingButNotEnforced", // Start in report-only mode
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "excludeGroups": exclude_group_ids,
                "excludeRoles": []
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": []
            },
            "locations": {
                "includeLocations": ["All"],
                "excludeLocations": []
            },
            "clientAppTypes": ["all"]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
            "customAuthenticationFactors": [],
            "termsOfUse": []
        },
        "sessionControls": null
    })
}

/// Generate GeoIP blocking Named Location (US + Canada only)
pub fn generate_us_canada_location(name: &str) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.countryNamedLocation",
        "displayName": name,
        "countriesAndRegions": ["US", "CA"],
        "includeUnknownCountriesAndRegions": false
    })
}

/// Generate GeoIP blocking CA policy (Block access from outside US/Canada)
pub fn generate_geoip_block_policy(
    name: &str,
    named_location_id: &str,
    exclude_group_ids: Vec<String>,
) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.conditionalAccessPolicy",
        "displayName": name,
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "excludeGroups": exclude_group_ids,
                "excludeRoles": []
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": []
            },
            "locations": {
                "includeLocations": ["All"],
                "excludeLocations": [named_location_id]
            },
            "clientAppTypes": ["all"]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
            "customAuthenticationFactors": [],
            "termsOfUse": []
        },
        "sessionControls": null
    })
}

/// Generate compliant device requirement policy
pub fn generate_compliant_device_policy(
    name: &str,
    platform: &str,
    exclude_group_ids: Vec<String>,
) -> Value {
    // Platform filter for device.filter condition (prepared for future use)
    let _platform_filter = match platform {
        "windows" => "device.operatingSystem eq \"Windows\"",
        "macos" => "device.operatingSystem eq \"macOS\"",
        "ios" => "device.operatingSystem eq \"iOS\"",
        "android" => "device.operatingSystem eq \"Android\"",
        _ => "device.operatingSystem eq \"Windows\"",
    };

    json!({
        "@odata.type": "#microsoft.graph.conditionalAccessPolicy",
        "displayName": name,
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "excludeGroups": exclude_group_ids,
                "excludeRoles": []
            },
            "applications": {
                "includeApplications": ["Office365"],
                "excludeApplications": []
            },
            "platforms": {
                "includePlatforms": [platform],
                "excludePlatforms": []
            },
            "clientAppTypes": ["all"]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["compliantDevice", "domainJoinedDevice"],
            "customAuthenticationFactors": [],
            "termsOfUse": []
        },
        "sessionControls": null
    })
}

/// Generate block legacy authentication policy
pub fn generate_block_legacy_auth_policy(name: &str, exclude_group_ids: Vec<String>) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.conditionalAccessPolicy",
        "displayName": name,
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "excludeGroups": exclude_group_ids,
                "excludeRoles": []
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": []
            },
            "clientAppTypes": [
                "exchangeActiveSync",
                "other"
            ]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
            "customAuthenticationFactors": [],
            "termsOfUse": []
        },
        "sessionControls": null
    })
}

/// Generate admin MFA policy (require MFA for all admin roles)
pub fn generate_admin_mfa_policy(name: &str) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.conditionalAccessPolicy",
        "displayName": name,
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {
                "includeRoles": [
                    "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
                    "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
                    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
                    "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
                    "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator
                    "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
                    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
                    "158c047a-c907-4556-b7ef-446551a6b5f7", // Cloud Application Administrator
                ],
                "excludeUsers": [],
                "excludeGroups": [],
                "excludeRoles": []
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": []
            },
            "clientAppTypes": ["all"]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
            "customAuthenticationFactors": [],
            "termsOfUse": []
        },
        "sessionControls": null
    })
}

/// Enable a CA policy (move from report-only to enforced)
pub async fn enable_policy(client: &GraphClient, policy_id: &str) -> Result<Value> {
    let payload = json!({
        "state": "enabled"
    });

    update_policy(client, policy_id, &payload).await
}

/// Set policy to report-only mode
pub async fn set_report_only(client: &GraphClient, policy_id: &str) -> Result<Value> {
    let payload = json!({
        "state": "enabledForReportingButNotEnforced"
    });

    update_policy(client, policy_id, &payload).await
}

/// Disable a CA policy
pub async fn disable_policy(client: &GraphClient, policy_id: &str) -> Result<Value> {
    let payload = json!({
        "state": "disabled"
    });

    update_policy(client, policy_id, &payload).await
}
