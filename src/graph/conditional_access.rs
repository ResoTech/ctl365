//! Conditional Access policy management via Microsoft Graph API
//!
//! Implements Zero Trust security patterns for Entra ID Conditional Access

#![allow(dead_code)]

use crate::error::Result;
use crate::graph::GraphClient;
use serde_json::{Value, json};

/// Create a Conditional Access policy
pub async fn create_policy(client: &GraphClient, policy: &Value) -> Result<Value> {
    client
        .post("identity/conditionalAccess/policies", policy)
        .await
}

/// List all Conditional Access policies
pub async fn list_policies(client: &GraphClient) -> Result<Value> {
    client.get("identity/conditionalAccess/policies").await
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

/// List Named Locations
pub async fn list_named_locations(client: &GraphClient) -> Result<Value> {
    client
        .get("identity/conditionalAccess/namedLocations")
        .await
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
