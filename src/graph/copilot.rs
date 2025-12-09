//! Microsoft 365 Copilot Graph API integration
//!
//! Provides agent catalog management, interaction export, and search capabilities
//! using Microsoft Graph API.
//!
//! Note: Some endpoints are in preview/beta and may change.
//! Agent catalog APIs are expected to be GA in December 2025.

use crate::error::Result;
use crate::graph::GraphClient;
use serde::{Deserialize, Serialize};

/// Agent package types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentPackageType {
    Microsoft,
    External,
    Shared,
    Custom,
    #[serde(other)]
    Unknown,
}

/// Copilot agent/app package from the catalog
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPackage {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub package_type: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub created_date_time: Option<String>,
    #[serde(default)]
    pub last_modified_date_time: Option<String>,
    #[serde(default)]
    pub is_enabled: Option<bool>,
    #[serde(default)]
    pub manifest: Option<AgentManifest>,
}

/// Agent manifest details
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentManifest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub short_description: Option<String>,
    #[serde(default)]
    pub full_description: Option<String>,
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    #[serde(default)]
    pub permissions: Option<Vec<AgentPermission>>,
    #[serde(default)]
    pub actions: Option<Vec<AgentAction>>,
}

/// Agent permission requirement
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPermission {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub permission_type: Option<String>,
}

/// Agent action/capability
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAction {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// List of agent packages response
#[derive(Debug, Deserialize)]
pub struct AgentPackageListResponse {
    pub value: Vec<AgentPackage>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
    #[serde(rename = "@odata.count")]
    pub count: Option<i64>,
}

/// Copilot interaction (for compliance/export)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CopilotInteraction {
    pub id: String,
    #[serde(default)]
    pub created_date_time: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub request_type: Option<String>,
    #[serde(default)]
    pub context_id: Option<String>,
}

/// List of interactions response
#[derive(Debug, Deserialize)]
pub struct InteractionListResponse {
    pub value: Vec<CopilotInteraction>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

/// Search request for Copilot
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRequest {
    pub requests: Vec<SearchQuery>,
}

/// Individual search query
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchQuery {
    pub entity_types: Vec<String>,
    pub query: SearchQueryText,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i32>,
}

/// Search query text
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchQueryText {
    pub query_string: String,
}

/// Search response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    pub value: Vec<SearchResultSet>,
}

/// Set of search results
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultSet {
    #[serde(default)]
    pub hits_containers: Option<Vec<HitsContainer>>,
}

/// Container for search hits
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HitsContainer {
    #[serde(default)]
    pub hits: Option<Vec<SearchHit>>,
    #[serde(default)]
    pub total: Option<i64>,
    #[serde(default)]
    pub more_results_available: Option<bool>,
}

/// Individual search hit
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    #[serde(default)]
    pub hit_id: Option<String>,
    #[serde(default)]
    pub rank: Option<i32>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub resource: Option<serde_json::Value>,
}

/// Meeting insights from Copilot
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeetingInsight {
    pub id: String,
    #[serde(default)]
    pub meeting_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub action_items: Option<Vec<ActionItem>>,
    #[serde(default)]
    pub key_topics: Option<Vec<String>>,
    #[serde(default)]
    pub created_date_time: Option<String>,
}

/// Action item from meeting
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionItem {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub assigned_to: Option<String>,
    #[serde(default)]
    pub due_date: Option<String>,
}

/// Copilot operations
pub struct CopilotClient<'a> {
    client: &'a GraphClient,
}

impl<'a> CopilotClient<'a> {
    pub fn new(client: &'a GraphClient) -> Self {
        Self { client }
    }

    // ========================================
    // Agent Catalog Management
    // ========================================

    /// List all agents and apps in the Copilot catalog
    ///
    /// Uses GET /copilot/admin/catalog/packages (GA December 2025)
    pub async fn list_agents(&self) -> Result<Vec<AgentPackage>> {
        let response: AgentPackageListResponse =
            self.client.get("copilot/admin/catalog/packages").await?;
        Ok(response.value)
    }

    /// List agents with filtering
    pub async fn list_agents_filtered(&self, filter: Option<&str>) -> Result<Vec<AgentPackage>> {
        let endpoint = match filter {
            Some(f) => format!(
                "copilot/admin/catalog/packages?$filter={}",
                urlencoding::encode(f)
            ),
            None => "copilot/admin/catalog/packages".to_string(),
        };
        let response: AgentPackageListResponse = self.client.get(&endpoint).await?;
        Ok(response.value)
    }

    /// Get a specific agent by ID
    ///
    /// Uses GET /copilot/admin/catalog/packages/{id}
    pub async fn get_agent(&self, agent_id: &str) -> Result<AgentPackage> {
        let endpoint = format!("copilot/admin/catalog/packages/{}", agent_id);
        self.client.get(&endpoint).await
    }

    /// List Microsoft first-party agents
    pub async fn list_microsoft_agents(&self) -> Result<Vec<AgentPackage>> {
        self.list_agents_filtered(Some("packageType eq 'microsoft'"))
            .await
    }

    /// List custom (organization-built) agents
    pub async fn list_custom_agents(&self) -> Result<Vec<AgentPackage>> {
        self.list_agents_filtered(Some("packageType eq 'custom'"))
            .await
    }

    /// List external (third-party) agents
    pub async fn list_external_agents(&self) -> Result<Vec<AgentPackage>> {
        self.list_agents_filtered(Some("packageType eq 'external'"))
            .await
    }

    // ========================================
    // Interaction Export (Compliance)
    // ========================================

    /// Export Copilot interactions for compliance
    ///
    /// Requires appropriate compliance permissions
    pub async fn export_interactions(
        &self,
        start_date: Option<&str>,
        end_date: Option<&str>,
    ) -> Result<Vec<CopilotInteraction>> {
        let mut endpoint = "copilot/interactions".to_string();

        let mut filters = Vec::new();
        if let Some(start) = start_date {
            filters.push(format!("createdDateTime ge {}", start));
        }
        if let Some(end) = end_date {
            filters.push(format!("createdDateTime le {}", end));
        }

        if !filters.is_empty() {
            endpoint = format!("{}?$filter={}", endpoint, filters.join(" and "));
        }

        let response: InteractionListResponse = self.client.get_beta(&endpoint).await?;
        Ok(response.value)
    }

    // ========================================
    // Search API
    // ========================================

    /// Search OneDrive and SharePoint content
    ///
    /// Uses POST /search/query
    pub async fn search_content(&self, query: &str, size: Option<i32>) -> Result<SearchResponse> {
        let request = SearchRequest {
            requests: vec![SearchQuery {
                entity_types: vec![
                    "driveItem".to_string(),
                    "listItem".to_string(),
                    "site".to_string(),
                ],
                query: SearchQueryText {
                    query_string: query.to_string(),
                },
                from: Some(0),
                size: size.or(Some(25)),
            }],
        };

        self.client.post("search/query", &request).await
    }

    /// Search for specific file types
    pub async fn search_files(
        &self,
        query: &str,
        file_type: Option<&str>,
    ) -> Result<SearchResponse> {
        let search_query = match file_type {
            Some(ft) => format!("{} filetype:{}", query, ft),
            None => query.to_string(),
        };

        self.search_content(&search_query, None).await
    }

    // ========================================
    // Meeting Insights (Preview)
    // ========================================

    /// Get meeting insights for a user
    pub async fn get_meeting_insights(&self, user_id: &str) -> Result<Vec<MeetingInsight>> {
        let endpoint = format!("users/{}/onlineMeetings/insights", user_id);

        #[derive(Deserialize)]
        struct InsightsResponse {
            value: Vec<MeetingInsight>,
        }

        let response: InsightsResponse = self.client.get_beta(&endpoint).await?;
        Ok(response.value)
    }

    /// Get insights for a specific meeting
    pub async fn get_meeting_insight(
        &self,
        user_id: &str,
        meeting_id: &str,
    ) -> Result<MeetingInsight> {
        let endpoint = format!("users/{}/onlineMeetings/{}/insights", user_id, meeting_id);
        self.client.get_beta(&endpoint).await
    }

    // ========================================
    // Change Notifications (Preview)
    // ========================================

    /// Subscribe to Copilot interaction changes
    ///
    /// Note: Requires webhook endpoint to receive notifications
    pub async fn subscribe_to_interactions(
        &self,
        webhook_url: &str,
        expiration_minutes: i32,
    ) -> Result<serde_json::Value> {
        let expiration = chrono::Utc::now() + chrono::Duration::minutes(expiration_minutes as i64);

        let subscription = serde_json::json!({
            "changeType": "created",
            "notificationUrl": webhook_url,
            "resource": "copilot/interactions",
            "expirationDateTime": expiration.to_rfc3339(),
            "clientState": "copilot-subscription"
        });

        self.client.post_beta("subscriptions", &subscription).await
    }
}

/// Builder for Copilot agent queries
pub struct AgentQueryBuilder {
    filters: Vec<String>,
    select: Vec<String>,
    top: Option<i32>,
    skip: Option<i32>,
}

impl AgentQueryBuilder {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            select: Vec::new(),
            top: None,
            skip: None,
        }
    }

    pub fn package_type(mut self, package_type: AgentPackageType) -> Self {
        let type_str = match package_type {
            AgentPackageType::Microsoft => "microsoft",
            AgentPackageType::External => "external",
            AgentPackageType::Shared => "shared",
            AgentPackageType::Custom => "custom",
            AgentPackageType::Unknown => return self,
        };
        self.filters.push(format!("packageType eq '{}'", type_str));
        self
    }

    pub fn enabled_only(mut self) -> Self {
        self.filters.push("isEnabled eq true".to_string());
        self
    }

    pub fn disabled_only(mut self) -> Self {
        self.filters.push("isEnabled eq false".to_string());
        self
    }

    pub fn publisher(mut self, publisher: &str) -> Self {
        self.filters.push(format!("publisher eq '{}'", publisher));
        self
    }

    pub fn top(mut self, count: i32) -> Self {
        self.top = Some(count);
        self
    }

    pub fn skip(mut self, count: i32) -> Self {
        self.skip = Some(count);
        self
    }

    pub fn select(mut self, fields: Vec<&str>) -> Self {
        self.select = fields.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn build(&self) -> String {
        let mut parts = Vec::new();

        if !self.filters.is_empty() {
            parts.push(format!("$filter={}", self.filters.join(" and ")));
        }

        if !self.select.is_empty() {
            parts.push(format!("$select={}", self.select.join(",")));
        }

        if let Some(top) = self.top {
            parts.push(format!("$top={}", top));
        }

        if let Some(skip) = self.skip {
            parts.push(format!("$skip={}", skip));
        }

        if parts.is_empty() {
            "copilot/admin/catalog/packages".to_string()
        } else {
            format!("copilot/admin/catalog/packages?{}", parts.join("&"))
        }
    }
}

impl Default for AgentQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
