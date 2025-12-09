//! Interactive TUI for tenant configuration
//!
//! Provides menu-driven and prompt-based configuration for M365 tenant settings.
//! Integrates with existing templates to provide smart defaults.
//!
//! ## Full TUI Mode (ratatui)
//! The `app` module provides a full-screen terminal UI with:
//! - Arrow key / vim-style navigation
//! - Number key quick selection
//! - Breadcrumb navigation and back functionality
//! - Help overlay
//!
//! ## Async Task Management
//! The `tasks` module provides non-blocking Graph API operations:
//! - Background tokio runtime for async calls
//! - Channel-based communication with TUI
//! - Progress reporting and error handling
//!
//! ## MSP Mode
//! The `msp` module provides multi-tenant client management with:
//! - Client abbreviations (RLAW, IRON, ITWO)
//! - App registration wizard
//! - Change tracking and client reporting

pub mod app;
pub mod change_tracker;
pub mod context;
pub mod menu;
pub mod msp;
pub mod prompts;
pub mod settings;
pub mod tasks;

pub use app::run_tui;
pub use menu::*;
pub use msp::run_msp_menu;
// RunContext is available for future CLI integration
#[allow(unused_imports)]
pub use context::RunContext;
