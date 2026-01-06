//! Intune Graph API operations
//!
//! Provides functions for managing Intune policies via Microsoft Graph API

#![allow(dead_code)]

use crate::error::{Error, Result};
use crate::graph::GraphClient;
use serde_json::Value;

/// Strip internal metadata fields from policy before sending to Graph API
fn clean_policy(policy: &Value) -> Value {
    let mut clean = policy.clone();
    if let Some(obj) = clean.as_object_mut() {
        // Remove internal ctl365 metadata
        obj.retain(|k, _| !k.starts_with("_ctl365_"));
    }
    clean
}

/// Create a policy in Intune via Microsoft Graph API
///
/// Routes the policy to the appropriate endpoint based on @odata.type
pub async fn create_policy(
    client: &GraphClient,
    odata_type: &str,
    policy: &Value,
) -> Result<Value> {
    // Settings Catalog policies require the beta endpoint
    if odata_type == "#microsoft.graph.deviceManagementConfigurationPolicy" {
        return client
            .post_beta("deviceManagement/configurationPolicies", policy)
            .await;
    }

    // Route to appropriate endpoint based on policy type
    let (endpoint, use_beta) = match odata_type {
        // Compliance policies
        "#microsoft.graph.windows10CompliancePolicy"
        | "#microsoft.graph.iosCompliancePolicy"
        | "#microsoft.graph.macOSCompliancePolicy"
        | "#microsoft.graph.androidCompliancePolicy" => {
            ("deviceManagement/deviceCompliancePolicies", false)
        }

        // Device configurations
        "#microsoft.graph.windows10EndpointProtectionConfiguration"
        | "#microsoft.graph.windows10CustomConfiguration"
        | "#microsoft.graph.macOSDeviceFeaturesConfiguration"
        | "#microsoft.graph.iosDeviceFeaturesConfiguration"
        | "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration" => {
            ("deviceManagement/deviceConfigurations", false)
        }

        // Security groups (Entra ID) - strip @odata.type before sending
        "#microsoft.graph.group" => {
            // Groups don't need @odata.type in the request body
            let mut cleaned = clean_policy(policy);
            if let Some(obj) = cleaned.as_object_mut() {
                obj.remove("@odata.type");
            }
            return client.post("groups", &cleaned).await;
        }

        // Windows Autopilot deployment profiles (requires beta endpoint)
        "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile"
        | "#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile" => {
            ("deviceManagement/windowsAutopilotDeploymentProfiles", true)
        }

        // Windows Update for Business - Update Rings
        "#microsoft.graph.windowsUpdateForBusinessConfiguration" => {
            ("deviceManagement/deviceConfigurations", false)
        }

        // Windows Feature Update profiles
        "#microsoft.graph.windowsFeatureUpdateProfile" => {
            ("deviceManagement/windowsFeatureUpdateProfiles", true)
        }

        _ => {
            return Err(Error::ConfigError(format!(
                "Unknown policy type: {}",
                odata_type
            )));
        }
    };

    let cleaned = clean_policy(policy);
    if use_beta {
        client.post_beta(endpoint, &cleaned).await
    } else {
        client.post(endpoint, &cleaned).await
    }
}

/// Assign a policy to a group
///
/// Creates an assignment linking the policy to an Azure AD group
pub async fn assign_policy(
    client: &GraphClient,
    odata_type: &str,
    policy_id: &str,
    group_id: &str,
) -> Result<Value> {
    let endpoint = if is_compliance_policy(odata_type) {
        format!(
            "deviceManagement/deviceCompliancePolicies/{}/assignments",
            policy_id
        )
    } else {
        format!(
            "deviceManagement/deviceConfigurations/{}/assignments",
            policy_id
        )
    };

    let assignment = serde_json::json!({
        "@odata.type": "#microsoft.graph.deviceConfigurationAssignment",
        "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": group_id
        }
    });

    client.post(&endpoint, &assignment).await
}

/// List all compliance policies in the tenant
pub async fn list_compliance_policies(client: &GraphClient) -> Result<Value> {
    client
        .get("deviceManagement/deviceCompliancePolicies")
        .await
}

/// List all device configurations in the tenant
pub async fn list_device_configurations(client: &GraphClient) -> Result<Value> {
    client.get("deviceManagement/deviceConfigurations").await
}

/// Get a specific compliance policy by ID
pub async fn get_compliance_policy(client: &GraphClient, policy_id: &str) -> Result<Value> {
    client
        .get(&format!(
            "deviceManagement/deviceCompliancePolicies/{}",
            policy_id
        ))
        .await
}

/// Get a specific device configuration by ID
pub async fn get_device_configuration(client: &GraphClient, config_id: &str) -> Result<Value> {
    client
        .get(&format!(
            "deviceManagement/deviceConfigurations/{}",
            config_id
        ))
        .await
}

/// Update an existing compliance policy
pub async fn update_compliance_policy(
    client: &GraphClient,
    policy_id: &str,
    policy: &Value,
) -> Result<Value> {
    client
        .patch(
            &format!("deviceManagement/deviceCompliancePolicies/{}", policy_id),
            policy,
        )
        .await
}

/// Update an existing device configuration
pub async fn update_device_configuration(
    client: &GraphClient,
    config_id: &str,
    config: &Value,
) -> Result<Value> {
    client
        .patch(
            &format!("deviceManagement/deviceConfigurations/{}", config_id),
            config,
        )
        .await
}

/// Delete a compliance policy
pub async fn delete_compliance_policy(client: &GraphClient, policy_id: &str) -> Result<()> {
    client
        .delete(&format!(
            "deviceManagement/deviceCompliancePolicies/{}",
            policy_id
        ))
        .await?;
    Ok(())
}

/// Delete a device configuration
pub async fn delete_device_configuration(client: &GraphClient, config_id: &str) -> Result<()> {
    client
        .delete(&format!(
            "deviceManagement/deviceConfigurations/{}",
            config_id
        ))
        .await?;
    Ok(())
}

/// List Azure AD groups (for assignment)
pub async fn list_groups(client: &GraphClient) -> Result<Value> {
    client.get("groups?$select=id,displayName").await
}

/// Search for a group by display name
pub async fn find_group_by_name(client: &GraphClient, name: &str) -> Result<Option<Value>> {
    let response: Value = client
        .get(&format!(
            "groups?$filter=displayName eq '{}'&$select=id,displayName",
            name
        ))
        .await?;

    let groups = response["value"]
        .as_array()
        .ok_or_else(|| Error::ConfigError("Invalid response from Graph API".into()))?;

    Ok(groups.first().cloned())
}

/// Get policy assignments
pub async fn get_policy_assignments(
    client: &GraphClient,
    odata_type: &str,
    policy_id: &str,
) -> Result<Value> {
    let endpoint = if is_compliance_policy(odata_type) {
        format!(
            "deviceManagement/deviceCompliancePolicies/{}/assignments",
            policy_id
        )
    } else {
        format!(
            "deviceManagement/deviceConfigurations/{}/assignments",
            policy_id
        )
    };

    client.get(&endpoint).await
}

/// Get device compliance status report
pub async fn get_device_compliance_status(client: &GraphClient) -> Result<Value> {
    client
        .get("deviceManagement/deviceCompliancePolicyDeviceStateSummary")
        .await
}

/// Get managed devices count
pub async fn get_managed_devices_count(client: &GraphClient) -> Result<usize> {
    let response: Value = client.get("deviceManagement/managedDevices/$count").await?;

    if let Some(count) = response.as_u64() {
        Ok(count as usize)
    } else {
        // Fallback: get the array and count it
        let devices: Value = client.get("deviceManagement/managedDevices").await?;
        Ok(devices["value"]
            .as_array()
            .map(|arr| arr.len())
            .unwrap_or(0))
    }
}

// Helper functions

fn is_compliance_policy(odata_type: &str) -> bool {
    matches!(
        odata_type,
        "#microsoft.graph.windows10CompliancePolicy"
            | "#microsoft.graph.iosCompliancePolicy"
            | "#microsoft.graph.macOSCompliancePolicy"
            | "#microsoft.graph.androidCompliancePolicy"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_compliance_policy() {
        assert!(is_compliance_policy(
            "#microsoft.graph.windows10CompliancePolicy"
        ));
        assert!(is_compliance_policy("#microsoft.graph.iosCompliancePolicy"));
        assert!(!is_compliance_policy(
            "#microsoft.graph.windows10EndpointProtectionConfiguration"
        ));
    }
}
