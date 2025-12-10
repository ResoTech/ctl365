pub mod auth;
pub mod conditional_access;
pub mod copilot;
pub mod defender;
pub mod exchange_online;
pub mod intune;
pub mod sharepoint;
pub mod viva;

use crate::config::ConfigManager;
use crate::error::{Ctl365Error, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const GRAPH_API_BASE: &str = "https://graph.microsoft.com/v1.0";
pub const GRAPH_API_BETA: &str = "https://graph.microsoft.com/beta";

/// Default retry configuration
const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 1000;
const MAX_BACKOFF_MS: u64 = 30000;
const JITTER_FACTOR: f64 = 0.3; // +/- 30% jitter

/// Calculate backoff with jitter for exponential backoff
fn calculate_backoff_with_jitter(attempt: u32) -> Duration {
    use std::time::Duration;

    // Base exponential backoff
    let base_backoff = INITIAL_BACKOFF_MS * 2u64.pow(attempt);

    // Cap the backoff
    let capped_backoff = base_backoff.min(MAX_BACKOFF_MS);

    // Add jitter (+/- JITTER_FACTOR)
    let jitter_range = (capped_backoff as f64 * JITTER_FACTOR) as u64;
    let jitter = if jitter_range > 0 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        (hasher.finish() % (jitter_range * 2)) as i64 - jitter_range as i64
    } else {
        0
    };

    let final_backoff = (capped_backoff as i64 + jitter).max(100) as u64;
    Duration::from_millis(final_backoff)
}

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
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let response = self
                .client
                .get(&url)
                .bearer_auth(&self.access_token)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    // Retry on 429 (rate limit) or 5xx (server errors)
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(INITIAL_BACKOFF_MS / 1000);

                        let wait_time = Duration::from_secs(retry_after);
                        eprintln!(
                            "Rate limited (429). Retrying in {} seconds... (attempt {}/{})",
                            retry_after,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if status.is_server_error() && attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        eprintln!(
                            "Server error ({}). Retrying in {:?}... (attempt {}/{})",
                            status,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if !status.is_success() {
                        let error_text = resp.text().await.unwrap_or_default();
                        let enhanced_error = crate::error::enhance_graph_error(&error_text);
                        return Err(Ctl365Error::GraphApiError(format!(
                            "HTTP {}: {}",
                            status, enhanced_error
                        )));
                    }

                    let data = resp.json::<T>().await?;
                    return Ok(data);
                }
                Err(e) => {
                    // Retry on connection errors
                    if attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        eprintln!(
                            "Connection error: {}. Retrying in {:?}... (attempt {}/{})",
                            e,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        last_error = Some(e);
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        // If we get here, all retries failed
        Err(last_error.map(|e| e.into()).unwrap_or_else(|| {
            Ctl365Error::GraphApiError(format!("GET {} failed after {} retries", url, MAX_RETRIES))
        }))
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
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let response = self
                .client
                .post(&url)
                .bearer_auth(&self.access_token)
                .json(body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    // Retry on 429 (rate limit) or 5xx (server errors)
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(INITIAL_BACKOFF_MS / 1000);

                        let wait_time = Duration::from_secs(retry_after);
                        eprintln!(
                            "Rate limited (429). Retrying in {} seconds... (attempt {}/{})",
                            retry_after,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if status.is_server_error() && attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        eprintln!(
                            "Server error ({}). Retrying in {:?}... (attempt {}/{})",
                            status,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if !status.is_success() {
                        let error_text = resp.text().await.unwrap_or_default();
                        let enhanced_error = crate::error::enhance_graph_error(&error_text);
                        return Err(Ctl365Error::GraphApiError(format!(
                            "HTTP {}: {}",
                            status, enhanced_error
                        )));
                    }

                    let data = resp.json::<R>().await?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        eprintln!(
                            "Connection error: {}. Retrying in {:?}... (attempt {}/{})",
                            e,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        last_error = Some(e);
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        Err(last_error.map(|e| e.into()).unwrap_or_else(|| {
            Ctl365Error::GraphApiError(format!("POST {} failed after {} retries", url, MAX_RETRIES))
        }))
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
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let response = self
                .client
                .patch(&url)
                .bearer_auth(&self.access_token)
                .json(body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(INITIAL_BACKOFF_MS / 1000);

                        let wait_time = Duration::from_secs(retry_after);
                        eprintln!(
                            "Rate limited (429). Retrying in {} seconds... (attempt {}/{})",
                            retry_after,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if status.is_server_error() && attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        eprintln!(
                            "Server error ({}). Retrying in {:?}... (attempt {}/{})",
                            status,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if !status.is_success() {
                        let error_text = resp.text().await.unwrap_or_default();
                        let enhanced_error = crate::error::enhance_graph_error(&error_text);
                        return Err(Ctl365Error::GraphApiError(format!(
                            "HTTP {}: {}",
                            status, enhanced_error
                        )));
                    }

                    let data = resp.json::<R>().await?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        eprintln!(
                            "Connection error: {}. Retrying in {:?}... (attempt {}/{})",
                            e,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        last_error = Some(e);
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        Err(last_error.map(|e| e.into()).unwrap_or_else(|| {
            Ctl365Error::GraphApiError(format!(
                "PATCH {} failed after {} retries",
                url, MAX_RETRIES
            ))
        }))
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
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let response = self
                .client
                .delete(&url)
                .bearer_auth(&self.access_token)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(INITIAL_BACKOFF_MS / 1000);

                        let wait_time = Duration::from_secs(retry_after);
                        eprintln!(
                            "Rate limited (429). Retrying in {} seconds... (attempt {}/{})",
                            retry_after,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if status.is_server_error() && attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        eprintln!(
                            "Server error ({}). Retrying in {:?}... (attempt {}/{})",
                            status,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if !status.is_success() {
                        let error_text = resp.text().await.unwrap_or_default();
                        let enhanced_error = crate::error::enhance_graph_error(&error_text);
                        return Err(Ctl365Error::GraphApiError(format!(
                            "HTTP {}: {}",
                            status, enhanced_error
                        )));
                    }

                    return Ok(());
                }
                Err(e) => {
                    if attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        eprintln!(
                            "Connection error: {}. Retrying in {:?}... (attempt {}/{})",
                            e,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(wait_time).await;
                        last_error = Some(e);
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        Err(last_error.map(|e| e.into()).unwrap_or_else(|| {
            Ctl365Error::GraphApiError(format!(
                "DELETE {} failed after {} retries",
                url, MAX_RETRIES
            ))
        }))
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
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let response = self
                .client
                .get(url)
                .bearer_auth(&self.access_token)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(INITIAL_BACKOFF_MS / 1000);

                        let wait_time = Duration::from_secs(retry_after);
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if status.is_server_error() && attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }

                    if !status.is_success() {
                        let error_text = resp.text().await.unwrap_or_default();
                        let enhanced_error = crate::error::enhance_graph_error(&error_text);
                        return Err(Ctl365Error::GraphApiError(format!(
                            "HTTP {}: {}",
                            status, enhanced_error
                        )));
                    }

                    let data = resp.json::<T>().await?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff_with_jitter(attempt);
                        tokio::time::sleep(wait_time).await;
                        last_error = Some(e);
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        Err(last_error.map(|e| e.into()).unwrap_or_else(|| {
            Ctl365Error::GraphApiError(format!("GET {} failed after {} retries", url, MAX_RETRIES))
        }))
    }
}
