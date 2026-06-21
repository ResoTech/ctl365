//! Retry logic for Graph API requests with exponential backoff and jitter.
//!
//! This module provides a centralized implementation of retry logic used by all
//! Graph API HTTP methods. It handles:
//! - Rate limiting (HTTP 429) with Retry-After header support
//! - Server errors (5xx) with exponential backoff
//! - Connection errors with exponential backoff
//! - Jitter to prevent thundering herd

use crate::error::{Ctl365Error, Result};
use rand::RngExt;
use reqwest::{Response, StatusCode};
use serde::Deserialize;
use std::future::Future;
use std::time::Duration;

/// Maximum number of retry attempts
pub const MAX_RETRIES: u32 = 3;
/// Initial backoff duration in milliseconds
const INITIAL_BACKOFF_MS: u64 = 1000;
/// Maximum backoff duration in milliseconds
const MAX_BACKOFF_MS: u64 = 30000;
/// Jitter factor (+/- 30%)
const JITTER_FACTOR: f64 = 0.3;

/// Calculate backoff duration with jitter for exponential backoff
pub fn calculate_backoff_with_jitter(attempt: u32) -> Duration {
    // Base exponential backoff: 1s, 2s, 4s, 8s...
    let base_backoff = INITIAL_BACKOFF_MS * 2u64.pow(attempt);

    // Cap the backoff at maximum
    let capped_backoff = base_backoff.min(MAX_BACKOFF_MS);

    // Add jitter (+/- JITTER_FACTOR) using proper RNG
    let jitter_range = (capped_backoff as f64 * JITTER_FACTOR) as i64;
    let jitter = if jitter_range > 0 {
        rand::rng().random_range(-jitter_range..=jitter_range)
    } else {
        0
    };

    let final_backoff = (capped_backoff as i64 + jitter).max(100) as u64;
    Duration::from_millis(final_backoff)
}

/// Parse the Retry-After header from a response
fn parse_retry_after(resp: &Response) -> Duration {
    let seconds = resp
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(INITIAL_BACKOFF_MS / 1000);
    Duration::from_secs(seconds)
}

/// Execute an HTTP request with retry logic, returning a JSON-deserialized response.
///
/// # Arguments
/// * `method` - HTTP method name for error messages (e.g., "GET", "POST")
/// * `url` - Full URL being requested
/// * `send_request` - Closure that builds and sends the request
/// * `verbose` - Whether to log retry attempts to stderr
///
/// # Type Parameters
/// * `T` - Response type to deserialize
/// * `F` - Closure type
/// * `Fut` - Future type returned by closure
pub async fn execute_json<T, F, Fut>(
    method: &str,
    url: &str,
    send_request: F,
    verbose: bool,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    F: Fn() -> Fut,
    Fut: Future<Output = std::result::Result<Response, reqwest::Error>>,
{
    let mut last_error = None;

    for attempt in 0..MAX_RETRIES {
        match send_request().await {
            Ok(resp) => {
                let status = resp.status();

                // Handle rate limiting (429)
                if status == StatusCode::TOO_MANY_REQUESTS {
                    let wait_time = parse_retry_after(&resp);
                    if verbose {
                        eprintln!(
                            "Rate limited (429). Retrying in {} seconds... (attempt {}/{})",
                            wait_time.as_secs(),
                            attempt + 1,
                            MAX_RETRIES
                        );
                    }
                    tokio::time::sleep(wait_time).await;
                    continue;
                }

                // Handle server errors (5xx)
                if status.is_server_error() && attempt < MAX_RETRIES - 1 {
                    let wait_time = calculate_backoff_with_jitter(attempt);
                    if verbose {
                        eprintln!(
                            "Server error ({}). Retrying in {:?}... (attempt {}/{})",
                            status,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                    }
                    tokio::time::sleep(wait_time).await;
                    continue;
                }

                // Handle non-success responses
                if !status.is_success() {
                    let error_text = resp.text().await.unwrap_or_default();
                    let enhanced_error = crate::error::enhance_graph_error(&error_text);
                    return Err(Ctl365Error::GraphApiError(format!(
                        "HTTP {}: {}",
                        status, enhanced_error
                    )));
                }

                // Parse JSON response
                let data = resp.json::<T>().await?;
                return Ok(data);
            }
            Err(e) => {
                // Handle connection errors
                if attempt < MAX_RETRIES - 1 {
                    let wait_time = calculate_backoff_with_jitter(attempt);
                    if verbose {
                        eprintln!(
                            "Connection error: {}. Retrying in {:?}... (attempt {}/{})",
                            e,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                    }
                    tokio::time::sleep(wait_time).await;
                    last_error = Some(e);
                    continue;
                }
                return Err(e.into());
            }
        }
    }

    // All retries exhausted
    Err(last_error.map(|e| e.into()).unwrap_or_else(|| {
        Ctl365Error::GraphApiError(format!(
            "{} {} failed after {} retries",
            method, url, MAX_RETRIES
        ))
    }))
}

/// Execute an HTTP request with retry logic, expecting no response body (204 No Content).
///
/// # Arguments
/// * `method` - HTTP method name for error messages
/// * `url` - Full URL being requested
/// * `send_request` - Closure that builds and sends the request
/// * `verbose` - Whether to log retry attempts to stderr
pub async fn execute_no_content<F, Fut>(
    method: &str,
    url: &str,
    send_request: F,
    verbose: bool,
) -> Result<()>
where
    F: Fn() -> Fut,
    Fut: Future<Output = std::result::Result<Response, reqwest::Error>>,
{
    let mut last_error = None;

    for attempt in 0..MAX_RETRIES {
        match send_request().await {
            Ok(resp) => {
                let status = resp.status();

                // Handle rate limiting (429)
                if status == StatusCode::TOO_MANY_REQUESTS {
                    let wait_time = parse_retry_after(&resp);
                    if verbose {
                        eprintln!(
                            "Rate limited (429). Retrying in {} seconds... (attempt {}/{})",
                            wait_time.as_secs(),
                            attempt + 1,
                            MAX_RETRIES
                        );
                    }
                    tokio::time::sleep(wait_time).await;
                    continue;
                }

                // Handle server errors (5xx)
                if status.is_server_error() && attempt < MAX_RETRIES - 1 {
                    let wait_time = calculate_backoff_with_jitter(attempt);
                    if verbose {
                        eprintln!(
                            "Server error ({}). Retrying in {:?}... (attempt {}/{})",
                            status,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                    }
                    tokio::time::sleep(wait_time).await;
                    continue;
                }

                // Handle non-success responses
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
                // Handle connection errors
                if attempt < MAX_RETRIES - 1 {
                    let wait_time = calculate_backoff_with_jitter(attempt);
                    if verbose {
                        eprintln!(
                            "Connection error: {}. Retrying in {:?}... (attempt {}/{})",
                            e,
                            wait_time,
                            attempt + 1,
                            MAX_RETRIES
                        );
                    }
                    tokio::time::sleep(wait_time).await;
                    last_error = Some(e);
                    continue;
                }
                return Err(e.into());
            }
        }
    }

    // All retries exhausted
    Err(last_error.map(|e| e.into()).unwrap_or_else(|| {
        Ctl365Error::GraphApiError(format!(
            "{} {} failed after {} retries",
            method, url, MAX_RETRIES
        ))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_increases_with_attempts() {
        // Note: Due to jitter, we test that base backoff increases
        // by checking multiple samples
        let mut samples_0: Vec<u64> = Vec::new();
        let mut samples_2: Vec<u64> = Vec::new();

        for _ in 0..10 {
            samples_0.push(calculate_backoff_with_jitter(0).as_millis() as u64);
            samples_2.push(calculate_backoff_with_jitter(2).as_millis() as u64);
        }

        let avg_0: u64 = samples_0.iter().sum::<u64>() / 10;
        let avg_2: u64 = samples_2.iter().sum::<u64>() / 10;

        // Attempt 2 should have ~4x the backoff of attempt 0 (2^2 = 4)
        assert!(avg_2 > avg_0 * 2, "Backoff should increase with attempts");
    }

    #[test]
    fn test_backoff_has_minimum() {
        let duration = calculate_backoff_with_jitter(0);
        assert!(
            duration.as_millis() >= 100,
            "Backoff should be at least 100ms"
        );
    }

    #[test]
    fn test_backoff_respects_cap() {
        // Even at high attempt counts, should not exceed MAX_BACKOFF_MS + jitter
        let duration = calculate_backoff_with_jitter(10);
        let max_with_jitter = MAX_BACKOFF_MS + (MAX_BACKOFF_MS as f64 * JITTER_FACTOR) as u64;
        assert!(
            duration.as_millis() <= max_with_jitter as u128,
            "Backoff should be capped"
        );
    }
}
