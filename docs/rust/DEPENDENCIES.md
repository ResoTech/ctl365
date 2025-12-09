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
| **colored** | 2.1 | Terminal colored output |
| **indicatif** | 0.17 | Progress bars and spinners |
| **dialoguer** | 0.11 | Interactive prompts and menus |
| **console** | 0.15 | Terminal manipulation |

### TUI Framework

| Crate | Version | Purpose |
|-------|---------|---------|
| **ratatui** | 0.29 | Terminal UI framework (successor to tui-rs) |
| **crossterm** | 0.28 | Cross-platform terminal handling |
| **tui-input** | 0.11 | Text input widget for ratatui |
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

### Authentication

| Crate | Version | Purpose |
|-------|---------|---------|
| **oauth2** | 4.4 | OAuth2 device code and client credentials flows |

### Serialization

| Crate | Version | Purpose |
|-------|---------|---------|
| **serde** | 1.0 | Serialization/deserialization framework |
| **serde_json** | 1.0 | JSON support |
| **toml** | 0.8 | TOML config file support |
| **csv** | 1.3 | CSV parsing for Autopilot imports |

### Error Handling

| Crate | Version | Purpose |
|-------|---------|---------|
| **anyhow** | 1.0 | Flexible error handling for applications |
| **thiserror** | 1.0 | Derive macros for custom error types |

### Utilities

| Crate | Version | Purpose |
|-------|---------|---------|
| **chrono** | 0.4 | Date/time handling |
| **uuid** | 1.10 | UUID generation and parsing |
| **url** | 2.5 | URL parsing |
| **urlencoding** | 2.1 | URL encoding/decoding |
| **zip** | 2.2 | ZIP file handling for .intunewin packages |
| **walkdir** | 2.5 | Directory traversal |
| **base64** | 0.22 | Base64 encoding/decoding |
| **directories** | 5.0 | Platform-specific config directories |
| **lazy_static** | 1.5 | Lazy initialization of statics |

### Logging

| Crate | Version | Purpose |
|-------|---------|---------|
| **tracing** | 0.1 | Application-level tracing |
| **tracing-subscriber** | 0.3 | Subscriber for tracing with env-filter |

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
dialoguer = { version = "0.11", features = ["fuzzy-select"] }
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

```bash
# Check for outdated dependencies
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

- [TESTING.md](TESTING.md) - Test infrastructure documentation
- [Cargo.toml](/Cargo.toml) - Full dependency list
- [Rust Edition Guide](https://doc.rust-lang.org/edition-guide/)
