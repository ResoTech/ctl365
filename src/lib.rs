//! CTL365 - Enterprise-grade Microsoft 365 deployment automation
//!
//! This library provides the core functionality for the ctl365 CLI tool.
//! It includes modules for Graph API interaction, configuration management,
//! template generation, and terminal UI components.

#![recursion_limit = "256"]
#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::single_char_add_str)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::vec_init_then_push)]

pub mod cmd;
pub mod config;
pub mod error;
pub mod graph;
pub mod templates;
pub mod tui;
