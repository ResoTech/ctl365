//! Viva Engage Graph API integration
//!
//! Provides community management and role assignment for Viva Engage
//! using Microsoft Graph API.

use crate::error::Result;
use crate::graph::GraphClient;
use serde::{Deserialize, Serialize};

/// Viva Engage community privacy settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommunityPrivacy {
    Public,
    Private,
}

impl Default for CommunityPrivacy {
    fn default() -> Self {
        CommunityPrivacy::Public
    }
}

/// Viva Engage role types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VivaRole {
    /// Network Administrator - full admin access
    NetworkAdmin,
    /// Verified Administrator - can manage compliance
    VerifiedAdmin,
    /// Corporate Communicator - can post official communications
    CorporateCommunicator,
    /// Answers Administrator - can manage Q&A features
    AnswersAdmin,
}

impl VivaRole {
    pub fn role_id(&self) -> &'static str {
        match self {
            VivaRole::NetworkAdmin => "62e90394-69f5-4237-9190-012177145e10",
            VivaRole::VerifiedAdmin => "e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477",
            VivaRole::CorporateCommunicator => "cf1c38e5-3621-4004-a7cb-879624dced7c",
            VivaRole::AnswersAdmin => "f023fd81-a637-4b56-95fd-791ac0226033",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            VivaRole::NetworkAdmin => "Network Administrator",
            VivaRole::VerifiedAdmin => "Verified Administrator",
            VivaRole::CorporateCommunicator => "Corporate Communicator",
            VivaRole::AnswersAdmin => "Answers Administrator",
        }
    }
}

/// Request body for creating a community
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCommunityRequest {
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub privacy: CommunityPrivacy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<UserReference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<UserReference>>,
}

/// User reference for community membership
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserReference {
    #[serde(rename = "@odata.id")]
    pub odata_id: String,
}

impl UserReference {
    pub fn from_user_id(user_id: &str) -> Self {
        Self {
            odata_id: format!("https://graph.microsoft.com/v1.0/users/{}", user_id),
        }
    }
}

/// Viva Engage community
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Community {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub privacy: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub created_date_time: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
}

/// List of communities response
#[derive(Debug, Deserialize)]
pub struct CommunityListResponse {
    pub value: Vec<Community>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

/// Role assignment for Viva Engage
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAssignment {
    #[serde(default)]
    pub id: Option<String>,
    pub role_template_id: String,
    pub principal_id: String,
    #[serde(default)]
    pub directory_scope_id: Option<String>,
}

/// Role assignment response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAssignmentResponse {
    pub id: String,
    pub role_template_id: String,
    pub principal_id: String,
}

/// List of role assignments response
#[derive(Debug, Deserialize)]
pub struct RoleAssignmentListResponse {
    pub value: Vec<RoleAssignment>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

/// Viva Connections dashboard card
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardCard {
    pub id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub card_type: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
}

/// Viva Engage operations
pub struct VivaClient<'a> {
    client: &'a GraphClient,
}

impl<'a> VivaClient<'a> {
    pub fn new(client: &'a GraphClient) -> Self {
        Self { client }
    }

    // ========================================
    // Community Management
    // ========================================

    /// Create a new Viva Engage community
    ///
    /// Uses POST /employeeExperience/communities
    pub async fn create_community(
        &self,
        display_name: &str,
        description: Option<&str>,
        privacy: CommunityPrivacy,
        owner_ids: Option<Vec<String>>,
    ) -> Result<Community> {
        let owners = owner_ids.map(|ids| {
            ids.into_iter()
                .map(|id| UserReference::from_user_id(&id))
                .collect()
        });

        let request = CreateCommunityRequest {
            display_name: display_name.to_string(),
            description: description.map(|s| s.to_string()),
            privacy,
            owners,
            members: None,
        };

        self.client
            .post("employeeExperience/communities", &request)
            .await
    }

    /// List all Viva Engage communities
    pub async fn list_communities(&self) -> Result<Vec<Community>> {
        let response: CommunityListResponse = self
            .client
            .get("employeeExperience/communities")
            .await?;
        Ok(response.value)
    }

    /// Get a specific community by ID
    pub async fn get_community(&self, community_id: &str) -> Result<Community> {
        let endpoint = format!("employeeExperience/communities/{}", community_id);
        self.client.get(&endpoint).await
    }

    /// Delete a community
    pub async fn delete_community(&self, community_id: &str) -> Result<()> {
        let endpoint = format!("employeeExperience/communities/{}", community_id);
        self.client.delete(&endpoint).await
    }

    /// Add a member to a community
    pub async fn add_community_member(
        &self,
        community_id: &str,
        user_id: &str,
    ) -> Result<()> {
        let endpoint = format!(
            "employeeExperience/communities/{}/members/$ref",
            community_id
        );
        let request = serde_json::json!({
            "@odata.id": format!("https://graph.microsoft.com/v1.0/users/{}", user_id)
        });
        self.client
            .post::<serde_json::Value, serde_json::Value>(&endpoint, &request)
            .await?;
        Ok(())
    }

    /// Remove a member from a community
    pub async fn remove_community_member(
        &self,
        community_id: &str,
        user_id: &str,
    ) -> Result<()> {
        let endpoint = format!(
            "employeeExperience/communities/{}/members/{}/$ref",
            community_id, user_id
        );
        self.client.delete(&endpoint).await
    }

    // ========================================
    // Role Management (Beta API)
    // ========================================

    /// Assign a Viva Engage role to a user
    ///
    /// Uses POST /beta/roleManagement/directory/roleAssignments
    pub async fn assign_role(
        &self,
        user_id: &str,
        role: VivaRole,
    ) -> Result<RoleAssignmentResponse> {
        let assignment = RoleAssignment {
            id: None,
            role_template_id: role.role_id().to_string(),
            principal_id: user_id.to_string(),
            directory_scope_id: Some("/".to_string()),
        };

        self.client
            .post_beta("roleManagement/directory/roleAssignments", &assignment)
            .await
    }

    /// List role assignments for a specific role
    pub async fn list_role_assignments(&self, role: VivaRole) -> Result<Vec<RoleAssignment>> {
        let endpoint = format!(
            "roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{}'",
            role.role_id()
        );
        let response: RoleAssignmentListResponse = self.client.get_beta(&endpoint).await?;
        Ok(response.value)
    }

    /// Remove a role assignment
    pub async fn revoke_role(&self, assignment_id: &str) -> Result<()> {
        let endpoint = format!(
            "roleManagement/directory/roleAssignments/{}",
            assignment_id
        );
        self.client.delete_beta(&endpoint).await
    }

    /// List all Corporate Communicators
    pub async fn list_corporate_communicators(&self) -> Result<Vec<RoleAssignment>> {
        self.list_role_assignments(VivaRole::CorporateCommunicator)
            .await
    }

    /// List all Network Administrators
    pub async fn list_network_admins(&self) -> Result<Vec<RoleAssignment>> {
        self.list_role_assignments(VivaRole::NetworkAdmin).await
    }

    // ========================================
    // Viva Connections (Preview)
    // ========================================

    /// Get Viva Connections home site configuration
    pub async fn get_home_site(&self) -> Result<serde_json::Value> {
        self.client
            .get_beta("admin/sharepoint/settings")
            .await
    }

    /// Set the home site for Viva Connections
    pub async fn set_home_site(&self, site_url: &str) -> Result<()> {
        let request = serde_json::json!({
            "homeSiteUrl": site_url
        });
        self.client
            .patch_beta::<serde_json::Value, serde_json::Value>(
                "admin/sharepoint/settings",
                &request,
            )
            .await?;
        Ok(())
    }
}

/// Viva Learning integration
pub struct VivaLearningClient<'a> {
    client: &'a GraphClient,
}

impl<'a> VivaLearningClient<'a> {
    pub fn new(client: &'a GraphClient) -> Self {
        Self { client }
    }

    /// List learning providers
    pub async fn list_providers(&self) -> Result<serde_json::Value> {
        self.client
            .get_beta("employeeExperience/learningProviders")
            .await
    }

    /// Get learning course catalog
    pub async fn list_courses(&self, provider_id: &str) -> Result<serde_json::Value> {
        let endpoint = format!(
            "employeeExperience/learningProviders/{}/learningContents",
            provider_id
        );
        self.client.get_beta(&endpoint).await
    }
}

/// Viva Insights integration (requires additional licensing)
pub struct VivaInsightsClient<'a> {
    #[allow(dead_code)]
    client: &'a GraphClient,
}

impl<'a> VivaInsightsClient<'a> {
    pub fn new(client: &'a GraphClient) -> Self {
        Self { client }
    }

    // Note: Viva Insights APIs require additional licensing and specific permissions
    // These are placeholder methods for future implementation
}
