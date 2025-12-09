//! SharePoint Graph API integration
//!
//! Provides site provisioning, page management, and hub site configuration
//! using Microsoft Graph API (beta for site creation, v1.0 for pages).

use crate::error::Result;
use crate::graph::GraphClient;
use serde::{Deserialize, Serialize};

/// SharePoint site types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteType {
    /// Communication site (no M365 group)
    Communication,
    /// Team site with M365 group
    Team,
    /// Team site without M365 group
    TeamNoGroup,
}

impl SiteType {
    pub fn template(&self) -> &'static str {
        match self {
            SiteType::Communication => "sitepagepublishing#0",
            SiteType::Team => "group#0",
            SiteType::TeamNoGroup => "sts#3",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            SiteType::Communication => "Communication Site",
            SiteType::Team => "Team Site (with M365 Group)",
            SiteType::TeamNoGroup => "Team Site (no M365 Group)",
        }
    }
}

/// Request body for creating a SharePoint site
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSiteRequest {
    pub display_name: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public: Option<bool>,
}

/// Response from site creation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSiteResponse {
    pub id: String,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// SharePoint site information
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub created_date_time: Option<String>,
    #[serde(default)]
    pub is_personal_site: Option<bool>,
}

/// List of sites response
#[derive(Debug, Deserialize)]
pub struct SiteListResponse {
    pub value: Vec<Site>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

/// SharePoint page information
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SitePage {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub page_layout: Option<String>,
    #[serde(default)]
    pub created_date_time: Option<String>,
    #[serde(default)]
    pub last_modified_date_time: Option<String>,
}

/// List of pages response
#[derive(Debug, Deserialize)]
pub struct PageListResponse {
    pub value: Vec<SitePage>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

/// Request body for creating a page
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePageRequest {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    pub name: String,
    pub title: String,
    pub page_layout: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_comments: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_recommended_pages: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_area: Option<TitleArea>,
}

/// Page title area configuration
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TitleArea {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_gradient_effect: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_author: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_published_date: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_text_block_above_title: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_above_title: Option<String>,
}

/// Hub site information
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HubSite {
    pub id: String,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub site_url: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// List of hub sites response
#[derive(Debug, Deserialize)]
pub struct HubSiteListResponse {
    pub value: Vec<HubSite>,
}

/// SharePoint operations
pub struct SharePointClient<'a> {
    client: &'a GraphClient,
}

impl<'a> SharePointClient<'a> {
    pub fn new(client: &'a GraphClient) -> Self {
        Self { client }
    }

    /// Create a new SharePoint site (beta API)
    ///
    /// Uses POST /beta/sites with Sites.Create.All permission
    pub async fn create_site(
        &self,
        display_name: &str,
        name: &str,
        site_type: SiteType,
        description: Option<&str>,
        owners: Option<Vec<String>>,
        is_public: Option<bool>,
    ) -> Result<CreateSiteResponse> {
        let request = CreateSiteRequest {
            display_name: display_name.to_string(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            template: site_type.template().to_string(),
            owners,
            members: None,
            is_public,
        };

        self.client.post_beta("sites", &request).await
    }

    /// List all sites in the tenant
    pub async fn list_sites(&self) -> Result<Vec<Site>> {
        let response: SiteListResponse = self.client.get("sites?$top=100").await?;
        Ok(response.value)
    }

    /// Search for sites by keyword
    pub async fn search_sites(&self, query: &str) -> Result<Vec<Site>> {
        let endpoint = format!("sites?search={}", urlencoding::encode(query));
        let response: SiteListResponse = self.client.get(&endpoint).await?;
        Ok(response.value)
    }

    /// Get a specific site by ID
    pub async fn get_site(&self, site_id: &str) -> Result<Site> {
        let endpoint = format!("sites/{}", site_id);
        self.client.get(&endpoint).await
    }

    /// Get site by URL (hostname and path)
    pub async fn get_site_by_url(&self, hostname: &str, site_path: &str) -> Result<Site> {
        let endpoint = format!("sites/{}:{}", hostname, site_path);
        self.client.get(&endpoint).await
    }

    /// Delete a site (beta API)
    pub async fn delete_site(&self, site_id: &str) -> Result<()> {
        let endpoint = format!("sites/{}", site_id);
        self.client.delete_beta(&endpoint).await
    }

    /// List pages in a site
    pub async fn list_pages(&self, site_id: &str) -> Result<Vec<SitePage>> {
        let endpoint = format!("sites/{}/pages", site_id);
        let response: PageListResponse = self.client.get(&endpoint).await?;
        Ok(response.value)
    }

    /// Create a new page in a site
    pub async fn create_page(
        &self,
        site_id: &str,
        name: &str,
        title: &str,
        layout: PageLayout,
    ) -> Result<SitePage> {
        let request = CreatePageRequest {
            odata_type: "#microsoft.graph.sitePage".to_string(),
            name: format!("{}.aspx", name),
            title: title.to_string(),
            page_layout: layout.as_str().to_string(),
            show_comments: Some(true),
            show_recommended_pages: Some(true),
            title_area: Some(TitleArea {
                enable_gradient_effect: Some(true),
                layout: Some("plain".to_string()),
                show_author: Some(true),
                show_published_date: Some(true),
                show_text_block_above_title: Some(false),
                text_above_title: None,
            }),
        };

        let endpoint = format!("sites/{}/pages", site_id);
        self.client.post(&endpoint, &request).await
    }

    /// Get a specific page
    pub async fn get_page(&self, site_id: &str, page_id: &str) -> Result<SitePage> {
        let endpoint = format!("sites/{}/pages/{}", site_id, page_id);
        self.client.get(&endpoint).await
    }

    /// Delete a page
    pub async fn delete_page(&self, site_id: &str, page_id: &str) -> Result<()> {
        let endpoint = format!("sites/{}/pages/{}", site_id, page_id);
        self.client.delete(&endpoint).await
    }

    /// Publish a page (make it visible to users)
    pub async fn publish_page(&self, site_id: &str, page_id: &str) -> Result<()> {
        let endpoint = format!("sites/{}/pages/{}/publish", site_id, page_id);
        self.client
            .post::<serde_json::Value, serde_json::Value>(&endpoint, &serde_json::json!({}))
            .await?;
        Ok(())
    }

    /// List hub sites in the tenant (beta API)
    pub async fn list_hub_sites(&self) -> Result<Vec<HubSite>> {
        let response: HubSiteListResponse = self
            .client
            .get_beta("sites?$filter=isHubSite eq true")
            .await?;
        Ok(response.value)
    }

    /// Register a site as a hub site (requires SharePoint Admin)
    pub async fn register_hub_site(&self, site_id: &str, title: &str) -> Result<HubSite> {
        let request = serde_json::json!({
            "title": title
        });
        let endpoint = format!("sites/{}/hubSite", site_id);
        self.client.post_beta(&endpoint, &request).await
    }

    /// Associate a site with a hub site
    pub async fn join_hub_site(&self, site_id: &str, hub_site_id: &str) -> Result<()> {
        let request = serde_json::json!({
            "hubSiteId": hub_site_id
        });
        let endpoint = format!("sites/{}", site_id);
        self.client
            .patch::<serde_json::Value, serde_json::Value>(&endpoint, &request)
            .await?;
        Ok(())
    }
}

/// Page layout types
#[derive(Debug, Clone, Copy)]
pub enum PageLayout {
    /// Article page layout
    Article,
    /// Home page layout
    Home,
    /// Single web part app page
    SingleWebPartAppPage,
    /// Vertical section layout
    VerticalSection,
    /// Repost page
    RepostPage,
}

impl PageLayout {
    pub fn as_str(&self) -> &'static str {
        match self {
            PageLayout::Article => "article",
            PageLayout::Home => "home",
            PageLayout::SingleWebPartAppPage => "singleWebPartAppPage",
            PageLayout::VerticalSection => "verticalSection",
            PageLayout::RepostPage => "repostPage",
        }
    }
}

/// Landing page templates
pub mod templates {
    use super::*;

    /// Create a welcome/landing page configuration
    pub fn welcome_page(title: &str) -> CreatePageRequest {
        CreatePageRequest {
            odata_type: "#microsoft.graph.sitePage".to_string(),
            name: "Home.aspx".to_string(),
            title: title.to_string(),
            page_layout: "home".to_string(),
            show_comments: Some(false),
            show_recommended_pages: Some(true),
            title_area: Some(TitleArea {
                enable_gradient_effect: Some(true),
                layout: Some("imageAndTitle".to_string()),
                show_author: Some(false),
                show_published_date: Some(false),
                show_text_block_above_title: Some(true),
                text_above_title: Some("Welcome to".to_string()),
            }),
        }
    }

    /// Create a department landing page configuration
    pub fn department_page(department_name: &str) -> CreatePageRequest {
        CreatePageRequest {
            odata_type: "#microsoft.graph.sitePage".to_string(),
            name: format!("{}.aspx", department_name.replace(' ', "-")),
            title: department_name.to_string(),
            page_layout: "article".to_string(),
            show_comments: Some(true),
            show_recommended_pages: Some(true),
            title_area: Some(TitleArea {
                enable_gradient_effect: Some(false),
                layout: Some("plain".to_string()),
                show_author: Some(true),
                show_published_date: Some(true),
                show_text_block_above_title: Some(false),
                text_above_title: None,
            }),
        }
    }
}
