# Testing Guide

This document covers the ctl365 test infrastructure, how to run tests, and how to write new tests.

---

## Quick Start

```bash
# Run all tests (requires nightly for wiremock)
cargo +nightly test

# Run with output
cargo +nightly test -- --nocapture

# Run specific test
cargo +nightly test test_get_success

# Run tests in a specific file
cargo +nightly test --test graph_client_tests
```

**Important:** Tests require `cargo +nightly` due to wiremock 0.6.x using unstable Rust features.

---

## Test Structure

```
ctl365/
├── src/
│   └── templates/
│       ├── windows.rs     # Unit tests (mod tests)
│       ├── macos.rs       # Unit tests (mod tests)
│       ├── ios.rs         # Unit tests (mod tests)
│       └── android.rs     # Unit tests (mod tests)
└── tests/
    └── graph_client_tests.rs   # Integration tests
```

### Unit Tests

Unit tests live inside their source files in a `#[cfg(test)]` module:

```rust
// src/templates/windows.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_compliance_policy() {
        // ...
    }
}
```

### Integration Tests

Integration tests live in the `tests/` directory:

```rust
// tests/graph_client_tests.rs

#[tokio::test]
async fn test_get_success() {
    // ...
}
```

---

## Test Categories

### 1. Template Generator Tests

Located in `src/templates/*.rs`, these test baseline policy generation:

**Windows (`src/templates/windows.rs`):**
- `test_generate_compliance_policy` - Windows compliance policy structure
- `test_generate_baseline_structure` - Full baseline with all policies

**macOS (`src/templates/macos.rs`):**
- `test_generate_compliance_policy` - macOS compliance policy
- `test_generate_device_features` - Device feature restrictions
- `test_baseline_with_encryption` - FileVault settings
- `test_baseline_with_defender` - Defender for Endpoint
- `test_baseline_without_extras` - Minimal baseline
- `test_baseline_structure` - Full baseline structure
- `test_custom_min_os` - Custom OS version
- `test_default_min_os` - Default macOS 15.0

**iOS (`src/templates/ios.rs`):**
- `test_generate_compliance_policy` - iOS compliance policy
- `test_generate_device_restrictions` - Device restrictions
- `test_generate_app_protection` - MAM policies
- `test_baseline_with_defender` - Defender ATP integration
- `test_baseline_without_defender` - Basic baseline
- `test_baseline_structure` - Full policy count
- `test_custom_min_os` - Custom iOS version
- `test_default_min_os` - Default iOS 18.0
- `test_device_restrictions_values` - Specific restriction values

### 2. Graph Client Tests

Located in `tests/graph_client_tests.rs`, these test HTTP interactions:

**Success Cases:**
- `test_get_success` - Basic GET request
- `test_post_success` - POST with JSON body
- `test_patch_success` - PATCH update
- `test_delete_success` - DELETE (204 No Content)
- `test_beta_endpoint` - Beta API access

**Error Cases:**
- `test_rate_limit_with_retry_after` - 429 rate limiting
- `test_server_error_500` - 5xx errors
- `test_unauthorized_no_retry` - 401 (no retry)
- `test_forbidden_no_retry` - 403 (no retry)
- `test_post_bad_request_no_retry` - 400 (no retry)
- `test_not_found_no_retry` - 404 (no retry)
- `test_request_timeout` - Timeout handling

**Special Cases:**
- `test_batch_request_format` - Graph API batch requests

---

## Writing Tests

### Test Helper Pattern

Create reusable test helpers for common setup:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::baseline::NewArgs;

    fn create_test_args(name: &str, encryption: bool, defender: bool) -> NewArgs {
        NewArgs {
            platform: "macos".to_string(),
            encryption,
            defender,
            min_os: None,
            mde_onboarding: None,
            output: None,
            name: name.to_string(),
            template: "basic".to_string(),
        }
    }

    #[test]
    fn test_basic_functionality() {
        let args = create_test_args("Test", false, false);
        let result = generate_baseline(&args).unwrap();
        assert!(result["policies"].is_array());
    }
}
```

### Async Tests

Use `#[tokio::test]` for async tests:

```rust
#[tokio::test]
async fn test_async_operation() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/test"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    // Test code...
}
```

### Mocking HTTP with wiremock

```rust
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_api_call() {
    // Start mock server
    let server = MockServer::start().await;

    // Define mock response
    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "value": []
                }))
        )
        .expect(1)  // Assert it's called exactly once
        .mount(&server)
        .await;

    // Make request to mock server
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
}
```

### Testing Rate Limits

```rust
#[tokio::test]
async fn test_rate_limit_handling() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/limited"))
        .respond_with(
            ResponseTemplate::new(429)
                .append_header("Retry-After", "2")
                .set_body_string("Rate limited")
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/limited", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 429);
    assert!(response.headers().contains_key("retry-after"));
}
```

### Testing Timeouts

```rust
use std::time::Duration;

#[tokio::test]
async fn test_timeout() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(5))
        )
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
```

---

## Test Coverage

### Current Coverage

| Component | Tests | Status |
|-----------|-------|--------|
| Template: Windows | 2 | Basic |
| Template: macOS | 8 | Comprehensive |
| Template: iOS | 9 | Comprehensive |
| Template: Android | 0 | TODO |
| Graph Client | 13 | Comprehensive |
| **Total** | **32** | |

### Areas Needing Tests

- Android template generator
- CLI command parsing
- Configuration loading/saving
- Token refresh logic
- Actual Graph API retry logic (currently tests mock only)

---

## Running Tests

### All Tests

```bash
cargo +nightly test
```

### With Output

```bash
cargo +nightly test -- --nocapture
```

### Specific Test

```bash
cargo +nightly test test_generate_compliance_policy
```

### Specific Module

```bash
# Unit tests in windows.rs
cargo +nightly test templates::windows

# Integration tests
cargo +nightly test --test graph_client_tests
```

### With Verbose Output

```bash
cargo +nightly test -- --test-threads=1 --nocapture
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust (nightly)
        uses: dtolnay/rust-toolchain@nightly

      - name: Run tests
        run: cargo +nightly test
```

---

## Troubleshooting

### "error[E0658]: 'let' expressions in this position are unstable"

**Cause:** Running tests with stable Rust instead of nightly

**Solution:**
```bash
cargo +nightly test
```

### "cannot find struct NewArgs"

**Cause:** Test helper missing required fields

**Solution:** Ensure all `NewArgs` fields are provided:
```rust
NewArgs {
    platform: "windows".to_string(),
    encryption: true,
    defender: true,
    min_os: None,
    mde_onboarding: None,
    output: None,
    name: "Test".to_string(),
    template: "basic".to_string(),  // Don't forget this!
}
```

### Tests Hang

**Cause:** Async runtime not properly configured

**Solution:** Use `#[tokio::test]` for async tests:
```rust
#[tokio::test]  // Not just #[test]
async fn test_async() {
    // ...
}
```

---

## See Also

- [DEPENDENCIES.md](DEPENDENCIES.md) - wiremock and nightly requirements
- [Cargo.toml](/Cargo.toml) - Test dependencies
- [wiremock docs](https://docs.rs/wiremock) - HTTP mocking library
