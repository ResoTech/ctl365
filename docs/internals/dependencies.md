# Rust Dependencies

This document covers ctl365's Rust dependencies, configuration requirements, and known compatibility notes.

---

## Rust Version

**Required:** Rust 2024 Edition (nightly for tests)

```toml
[package]
edition = "2024"
```

### Why Nightly for Tests?

The test suite uses [wiremock](https://crates.io/crates/wiremock) for HTTP mocking. As of wiremock 0.6.x, it uses unstable Rust features (`let` chains) that require the nightly compiler.

**Building:**
```bash
# Building works on stable
cargo build --release
```

**Testing:**
```bash
# Tests require nightly
cargo +nightly test
```

If you don't have nightly installed:
```bash
rustup install nightly
```

---

## Core Dependencies

### CLI Framework

| Crate | Version | Purpose |
|-------|---------|---------|
| **clap** | 4.5 | Command-line argument parsing with derive macros |
| **colored** | 3.1 | Terminal colored output |
| **indicatif** | 0.18 | Progress bars and spinners |
| **dialoguer** | 0.12 | Interactive prompts and menus |

### TUI Framework

| Crate | Version | Purpose |
|-------|---------|---------|
| **ratatui** | 0.30 | Terminal UI framework (successor to tui-rs) |
| **crossterm** | 0.29 | Cross-platform terminal handling |
| **crossbeam-channel** | 0.5 | Multi-producer multi-consumer channels |

### Async Runtime

| Crate | Version | Purpose |
|-------|---------|---------|
| **tokio** | 1.40 | Async runtime with full features |

### HTTP Client

| Crate | Version | Purpose |
|-------|---------|---------|
| **reqwest** | 0.12 | HTTP client with JSON and rustls-tls |

**Note:** We use `rustls-tls` instead of native TLS for better cross-compilation support.

**Held at 0.12 (intentional):** reqwest is not upgraded to 0.13 because (1) oauth2 5.0 depends on `reqwest ^0.12` and the auth code shares a `&reqwest::Client` with it, and (2) reqwest 0.13's rustls feature defaults to the `aws-lc-rs` backend, which breaks the `x86_64-pc-windows-gnu` cross-compile used by the release workflow.

### Authentication

| Crate | Version | Purpose |
|-------|---------|---------|
| **oauth2** | 5.0 | OAuth2 device code and client credentials flows |

**Note:** oauth2 5.0 uses a typestate builder (`BasicClient::new(id).set_auth_uri(..).set_token_uri(..)`) and takes a shared `&reqwest::Client` per request. It depends on `reqwest ^0.12`, which is one reason reqwest is held at 0.12 (see HTTP Client below).

### Serialization

| Crate | Version | Purpose |
|-------|---------|---------|
| **serde** | 1.0 | Serialization/deserialization framework |
| **serde_json** | 1.0 | JSON support |
| **toml** | 1 | TOML config file support |
| **csv** | 1.3 | CSV parsing for Autopilot imports |

### Error Handling

| Crate | Version | Purpose |
|-------|---------|---------|
| **anyhow** | 1.0 | Flexible error handling for applications |
| **thiserror** | 2.0 | Derive macros for custom error types |

### Utilities

| Crate | Version | Purpose |
|-------|---------|---------|
| **chrono** | 0.4 | Date/time handling |
| **uuid** | 1.10 | UUID generation and parsing |
| **url** | 2.5 | URL parsing |
| **urlencoding** | 2.1 | URL encoding/decoding |
| **zip** | 8 | ZIP file handling for .intunewin packages |
| **walkdir** | 2.5 | Directory traversal |
| **base64** | 0.22 | Base64 encoding/decoding |
| **rand** | 0.10 | Jitter for retry backoff |
| **directories** | 6.0 | Platform-specific config and home directories |

### Logging

| Crate | Version | Purpose |
|-------|---------|---------|
| **tracing** | 0.1 | Application-level tracing |
| **tracing-subscriber** | 0.3 | Subscriber for tracing with env-filter |

### Standard Library Replacements

Two previously used helper crates have been dropped in favour of the standard library:

- **lazy_static** → `std::sync::LazyLock` (stable since Rust 1.80) for global statics in `src/tui/change_tracker.rs`.
- **dirs-next** → `directories::UserDirs` for resolving the home directory in `src/config/mod.rs`.

---

## Dev Dependencies

| Crate | Version | Purpose | Notes |
|-------|---------|---------|-------|
| **wiremock** | 0.6 | HTTP mocking for integration tests | **Requires nightly** |

### wiremock Compatibility

wiremock 0.6.x uses unstable Rust features:

```rust
// This syntax requires nightly:
if let Some(x) = opt && x > 0 {
    // ...
}
```

**Workarounds:**
1. Use `cargo +nightly test` (recommended)
2. Pin to wiremock 0.5.x (older API)
3. Wait for let chains to stabilize (tracking issue: rust-lang/rust#53667)

---

## Feature Flags

### clap

```toml
clap = { version = "4.5", features = ["derive", "cargo", "env"] }
```

- **derive**: Enables `#[derive(Parser)]` macros
- **cargo**: Cargo metadata integration
- **env**: Environment variable support for args

### reqwest

```toml
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
```

- **json**: JSON serialization/deserialization
- **rustls-tls**: Pure Rust TLS (no OpenSSL dependency)
- **default-features = false**: Excludes native-tls

### tokio

```toml
tokio = { version = "1.40", features = ["full"] }
```

- **full**: All tokio features (runtime, macros, io, fs, net, etc.)

### chrono

```toml
chrono = { version = "0.4", features = ["serde"] }
```

- **serde**: Serialization support for DateTime types

### uuid

```toml
uuid = { version = "1.10", features = ["serde", "v4"] }
```

- **serde**: Serialization support
- **v4**: Random UUID generation

### dialoguer

```toml
dialoguer = { version = "0.12", features = ["fuzzy-select"] }
```

- **fuzzy-select**: Fuzzy search in selection menus

### tracing-subscriber

```toml
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

- **env-filter**: RUST_LOG environment variable support

---

## Cross-Compilation

The project uses rustls-tls for cross-platform TLS support:

```bash
# Linux (native)
cargo build --release

# Windows cross-compile from Linux
cargo build --release --target x86_64-pc-windows-gnu
```

**Note:** Windows builds are placed in `/data/projects/ctl365/release/windows/`

---

## Updating Dependencies

Routine minor/patch bumps are handled automatically by [Dependabot](../../.github/dependabot.yml), which opens grouped weekly PRs for the `cargo` and `github-actions` ecosystems. Manual updates:

```bash
# Check for outdated dependencies (requires: cargo install cargo-outdated)
cargo outdated

# Update Cargo.lock
cargo update

# Update a specific dependency
cargo update -p reqwest
```

---

## Security Auditing

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit
```

---

## Known Issues

### 1. wiremock + stable Rust

**Issue:** wiremock 0.6.x doesn't compile on stable Rust
**Workaround:** Use `cargo +nightly test`
**Tracking:** Will be resolved when let chains stabilize

### 2. chrono RUSTSEC-2020-0159

**Issue:** chrono's `localtime_r` can cause segfaults on some platforms
**Status:** Mitigated in chrono 0.4.x with feature flags
**Note:** We don't use the affected functionality

---

## Version Pinning

The project uses semantic versioning in Cargo.toml. For reproducible builds, commit `Cargo.lock`:

```bash
git add Cargo.lock
git commit -m "Lock dependency versions"
```

---

## See Also

- [Rust Testing](../testing/rust-testing.md) - Test infrastructure documentation
- [Cargo.toml](/Cargo.toml) - Full dependency list
- [Rust Edition Guide](https://doc.rust-lang.org/edition-guide/)
