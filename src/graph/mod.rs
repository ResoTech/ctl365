pub mod auth;
pub mod conditional_access;
pub mod copilot;
pub mod defender;
pub mod exchange_online;
pub mod identity_protection;
pub mod intune;
pub mod retry;
pub mod sharepoint;
pub mod viva;

use crate::config::ConfigManager;
use crate::error::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub const GRAPH_API_BASE: &str = "https://graph.microsoft.com/v1.0";
pub const GRAPH_API_BETA: &str = "https://graph.microsoft.com/beta";

/// Rate limit configuration for Viva Engage (10 requests per 30 seconds)
#[allow(dead_code)]
const VIVA_RATE_LIMIT_REQUESTS: u32 = 10;
#[allow(dead_code)]
const VIVA_RATE_LIMIT_WINDOW_SECS: u64 = 30;

/// Graph API client with retry support
pub struct GraphClient {
    client: Client,
    access_token: String,
}

impl GraphClient {
    pub fn new(access_token: String) -> Self {
        Self {
            client: Client::new(),
            access_token,
        }
    }

    /// Create a GraphClient from ConfigManager and tenant name
    /// This will load or acquire a token for the specified tenant
    pub async fn from_config(config: &ConfigManager, tenant_name: &str) -> Result<Self> {
        let graph_auth = auth::GraphAuth::new(config.clone());
        let access_token = graph_auth.get_access_token(tenant_name).await?;

        Ok(Self::new(access_token))
    }

    /// Make a GET request to Graph API with retry for transient failures
    pub async fn get<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> Result<T> {
        self.get_with_retry(endpoint, GRAPH_API_BASE).await
    }

    /// Internal GET with retry and configurable base URL
    async fn get_with_retry<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        base_url: &str,
    ) -> Result<T> {
        let url = format!("{}/{}", base_url, endpoint.trim_start_matches('/'));
        let client = &self.client;
        let token = &self.access_token;

        retry::execute_json(
            "GET",
            &url,
            || client.get(&url).bearer_auth(token).send(),
            true,
        )
        .await
    }

    /// Make a POST request to Graph API with retry for transient failures
    pub async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<R> {
        self.post_with_retry(endpoint, body, GRAPH_API_BASE).await
    }

    /// Internal POST with retry and configurable base URL
    async fn post_with_retry<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: &T,
        base_url: &str,
    ) -> Result<R> {
        let url = format!("{}/{}", base_url, endpoint.trim_start_matches('/'));
        let body_json = serde_json::to_value(body).unwrap_or_default();
        let client = &self.client;
        let token = &self.access_token;

        retry::execute_json(
            "POST",
            &url,
            || client.post(&url).bearer_auth(token).json(&body_json).send(),
            true,
        )
        .await
    }

    /// Make a GET request to Graph API (beta endpoint) with retry
    pub async fn get_beta<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> Result<T> {
        self.get_with_retry(endpoint, GRAPH_API_BETA).await
    }

    /// Make a POST request to Graph API (beta endpoint) with retry
    pub async fn post_beta<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<R> {
        self.post_with_retry(endpoint, body, GRAPH_API_BETA).await
    }

    /// Make a PATCH request to Graph API with retry
    pub async fn patch<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<R> {
        self.patch_with_retry(endpoint, body, GRAPH_API_BASE).await
    }

    /// Make a PATCH request to Graph API (beta endpoint) with retry
    pub async fn patch_beta<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> Result<R> {
        self.patch_with_retry(endpoint, body, GRAPH_API_BETA).await
    }

    /// Internal PATCH with retry and configurable base URL
    async fn patch_with_retry<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: &T,
        base_url: &str,
    ) -> Result<R> {
        let url = format!("{}/{}", base_url, endpoint.trim_start_matches('/'));
        let body_json = serde_json::to_value(body).unwrap_or_default();
        let client = &self.client;
        let token = &self.access_token;

        retry::execute_json(
            "PATCH",
            &url,
            || {
                client
                    .patch(&url)
                    .bearer_auth(token)
                    .json(&body_json)
                    .send()
            },
            true,
        )
        .await
    }

    /// Make a PATCH request that expects no response body (204 No Content)
    pub async fn patch_no_response<T: Serialize>(&self, endpoint: &str, body: &T) -> Result<()> {
        let url = format!("{}/{}", GRAPH_API_BASE, endpoint.trim_start_matches('/'));
        let body_json = serde_json::to_value(body).unwrap_or_default();
        let client = &self.client;
        let token = &self.access_token;

        retry::execute_no_content(
            "PATCH",
            &url,
            || {
                client
                    .patch(&url)
                    .bearer_auth(token)
                    .json(&body_json)
                    .send()
            },
            false, // Quiet mode for no-response operations
        )
        .await
    }

    /// Make a DELETE request to Graph API with retry
    pub async fn delete(&self, endpoint: &str) -> Result<()> {
        self.delete_with_retry(endpoint, GRAPH_API_BASE).await
    }

    /// Make a DELETE request to Graph API (beta endpoint) with retry
    pub async fn delete_beta(&self, endpoint: &str) -> Result<()> {
        self.delete_with_retry(endpoint, GRAPH_API_BETA).await
    }

    /// Internal DELETE with retry and configurable base URL
    async fn delete_with_retry(&self, endpoint: &str, base_url: &str) -> Result<()> {
        let url = format!("{}/{}", base_url, endpoint.trim_start_matches('/'));
        let client = &self.client;
        let token = &self.access_token;

        retry::execute_no_content(
            "DELETE",
            &url,
            || client.delete(&url).bearer_auth(token).send(),
            true,
        )
        .await
    }

    /// Get raw response with headers (useful for long-running operations)
    pub async fn post_raw(
        &self,
        endpoint: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Response> {
        let url = format!("{}/{}", GRAPH_API_BETA, endpoint.trim_start_matches('/'));

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await?;

        Ok(response)
    }

    /// Poll for operation status (used for long-running operations like site creation)
    pub async fn poll_operation(&self, operation_url: &str) -> Result<OperationStatus> {
        self.get_beta(operation_url).await
    }
}

/// Status of a long-running operation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationStatus {
    pub status: String,
    #[serde(default)]
    pub percent_complete: Option<f64>,
    #[serde(default)]
    pub error: Option<OperationError>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationError {
    pub code: String,
    pub message: String,
}

// ============================================================================
// Pagination Helpers
// ============================================================================

/// Generic paginated response from Graph API
///
/// Use this for standard OData paginated responses with `value` array and `@odata.nextLink`
#[derive(Debug, Deserialize)]
pub struct PaginatedResponse<T> {
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
    #[serde(rename = "@odata.count")]
    pub count: Option<i64>,
}

impl GraphClient {
    /// Fetch all pages of a paginated Graph API endpoint
    ///
    /// Automatically follows `@odata.nextLink` until all pages are retrieved.
    ///
    /// # Arguments
    /// * `endpoint` - The initial API endpoint (e.g., "/users")
    ///
    /// # Returns
    /// A vector containing all items from all pages
    ///
    /// # Example
    /// ```ignore
    /// let all_users: Vec<User> = client.get_all_pages("/users").await?;
    /// ```
    pub async fn get_all_pages<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
    ) -> Result<Vec<T>> {
        self.get_all_pages_with_base(endpoint, GRAPH_API_BASE).await
    }

    /// Fetch all pages from a beta endpoint
    pub async fn get_all_pages_beta<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
    ) -> Result<Vec<T>> {
        self.get_all_pages_with_base(endpoint, GRAPH_API_BETA).await
    }

    /// Internal implementation for paginated fetching
    async fn get_all_pages_with_base<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        base_url: &str,
    ) -> Result<Vec<T>> {
        let mut all_items: Vec<T> = Vec::new();
        let mut current_url = format!("{}/{}", base_url, endpoint.trim_start_matches('/'));

        loop {
            let response: PaginatedResponse<T> = self.get_raw_url(&current_url).await?;
            all_items.extend(response.value);

            match response.next_link {
                Some(next) => current_url = next,
                None => break,
            }
        }

        Ok(all_items)
    }

    /// Fetch paginated results with a maximum page limit
    ///
    /// Useful for large datasets where you only need a subset
    ///
    /// # Arguments
    /// * `endpoint` - The initial API endpoint
    /// * `max_pages` - Maximum number of pages to fetch (0 = unlimited)
    pub async fn get_pages_limited<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        max_pages: usize,
    ) -> Result<Vec<T>> {
        let mut all_items: Vec<T> = Vec::new();
        let mut current_url = format!("{}/{}", GRAPH_API_BASE, endpoint.trim_start_matches('/'));
        let mut page_count = 0;

        loop {
            let response: PaginatedResponse<T> = self.get_raw_url(&current_url).await?;
            all_items.extend(response.value);
            page_count += 1;

            if max_pages > 0 && page_count >= max_pages {
                break;
            }

            match response.next_link {
                Some(next) => current_url = next,
                None => break,
            }
        }

        Ok(all_items)
    }

    /// Make a GET request to a raw URL (for following nextLink)
    async fn get_raw_url<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let client = &self.client;
        let token = &self.access_token;
        let url_owned = url.to_string();

        retry::execute_json(
            "GET",
            url,
            || client.get(&url_owned).bearer_auth(token).send(),
            false, // Quiet mode for pagination
        )
        .await
    }
}
