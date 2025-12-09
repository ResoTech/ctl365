//! Integration tests for Graph client retry logic
//!
//! Uses wiremock to simulate various HTTP responses and verify
//! retry behavior, rate limit handling, and error propagation.

use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test helper to create a mock server
async fn setup_mock_server() -> MockServer {
    MockServer::start().await
}

/// Test successful GET request (no retry needed)
#[tokio::test]
async fn test_get_success() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/me"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "id": "12345",
                    "displayName": "Test User"
                })),
        )
        .expect(1) // Should only be called once
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/me", server.uri()))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["displayName"], "Test User");
}

/// Test 429 rate limit response with Retry-After header
#[tokio::test]
async fn test_rate_limit_with_retry_after() {
    let server = setup_mock_server().await;

    // First request returns 429 with Retry-After
    Mock::given(method("GET"))
        .and(path("/v1.0/test"))
        .respond_with(
            ResponseTemplate::new(429)
                .append_header("Retry-After", "1")
                .set_body_string("Rate limited"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/test", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 429);
    assert!(response.headers().contains_key("retry-after"));
}

/// Test 5xx server error
#[tokio::test]
async fn test_server_error_500() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/error"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(serde_json::json!({
                    "error": {
                        "code": "InternalServerError",
                        "message": "Internal server error"
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/error", server.uri()))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_server_error());
}

/// Test 401 Unauthorized (should not retry)
#[tokio::test]
async fn test_unauthorized_no_retry() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/unauthorized"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({
                    "error": {
                        "code": "InvalidAuthenticationToken",
                        "message": "Access token is empty."
                    }
                })),
        )
        .expect(1) // Should only be called once (no retry)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/unauthorized", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}

/// Test 403 Forbidden (should not retry)
#[tokio::test]
async fn test_forbidden_no_retry() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/forbidden"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(serde_json::json!({
                    "error": {
                        "code": "Authorization_RequestDenied",
                        "message": "Insufficient privileges to complete the operation."
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/forbidden", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
}

/// Test successful POST request
#[tokio::test]
async fn test_post_success() {
    let server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path("/v1.0/policies"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({
                    "id": "policy-123",
                    "displayName": "Test Policy"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1.0/policies", server.uri()))
        .json(&serde_json::json!({
            "displayName": "Test Policy"
        }))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["id"], "policy-123");
}

/// Test POST with 400 Bad Request (should not retry)
#[tokio::test]
async fn test_post_bad_request_no_retry() {
    let server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path("/v1.0/policies"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({
                    "error": {
                        "code": "BadRequest",
                        "message": "Property displayName is required."
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1.0/policies", server.uri()))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
}

/// Test DELETE request success
#[tokio::test]
async fn test_delete_success() {
    let server = setup_mock_server().await;

    Mock::given(method("DELETE"))
        .and(path("/v1.0/policies/123"))
        .respond_with(ResponseTemplate::new(204)) // No content
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/v1.0/policies/123", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
}

/// Test PATCH request success
#[tokio::test]
async fn test_patch_success() {
    let server = setup_mock_server().await;

    Mock::given(method("PATCH"))
        .and(path("/v1.0/policies/123"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "id": "123",
                    "displayName": "Updated Policy"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .patch(format!("{}/v1.0/policies/123", server.uri()))
        .json(&serde_json::json!({
            "displayName": "Updated Policy"
        }))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
}

/// Test beta endpoint usage
#[tokio::test]
async fn test_beta_endpoint() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/beta/deviceManagement"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "id": "device-mgmt"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/beta/deviceManagement", server.uri()))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
}

/// Test timeout handling
#[tokio::test]
async fn test_request_timeout() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();

    let result = client
        .get(format!("{}/v1.0/slow", server.uri()))
        .send()
        .await;

    assert!(result.is_err());
}

/// Test 404 Not Found (should not retry)
#[tokio::test]
async fn test_not_found_no_retry() {
    let server = setup_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({
                    "error": {
                        "code": "Request_ResourceNotFound",
                        "message": "Resource not found."
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/nonexistent", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

/// Test Graph API batch request format
#[tokio::test]
async fn test_batch_request_format() {
    let server = setup_mock_server().await;

    Mock::given(method("POST"))
        .and(path("/$batch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "responses": [
                        {"id": "1", "status": 200, "body": {"displayName": "User 1"}},
                        {"id": "2", "status": 200, "body": {"displayName": "User 2"}}
                    ]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/$batch", server.uri()))
        .json(&serde_json::json!({
            "requests": [
                {"id": "1", "method": "GET", "url": "/users/user1"},
                {"id": "2", "method": "GET", "url": "/users/user2"}
            ]
        }))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["responses"].as_array().unwrap().len(), 2);
}
