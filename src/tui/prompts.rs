//! Interactive prompts for tenant configuration
//!
//! Provides y/n prompts, multi-select, and input prompts for configuring settings.

use crate::error::Result;
use colored::Colorize;
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};

/// Prompt for yes/no confirmation with a default value
pub fn confirm(message: &str, default: bool) -> Result<bool> {
    let result = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(message)
        .default(default)
        .interact()?;
    Ok(result)
}

/// Prompt for yes/no with explanation of what the setting does
pub fn confirm_with_help(message: &str, help: &str, default: bool) -> Result<bool> {
    println!("  {} {}", "Info:".cyan(), help);
    confirm(message, default)
}

/// Prompt for text input with a default value
pub fn input(message: &str, default: &str) -> Result<String> {
    let result: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(message)
        .default(default.to_string())
        .interact_text()?;
    Ok(result)
}

/// Prompt for numeric input with a default value
pub fn input_number(message: &str, default: u32) -> Result<u32> {
    let result: u32 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(message)
        .default(default)
        .interact_text()?;
    Ok(result)
}

/// Prompt for selection from a list of options
pub fn select<T: ToString>(message: &str, options: &[T], default: usize) -> Result<usize> {
    let items: Vec<String> = options.iter().map(|o| o.to_string()).collect();
    let result = Select::with_theme(&ColorfulTheme::default())
        .with_prompt(message)
        .items(&items)
        .default(default)
        .interact()?;
    Ok(result)
}

/// Prompt for multi-selection from a list of options
pub fn multi_select<T: ToString>(
    message: &str,
    options: &[T],
    defaults: &[bool],
) -> Result<Vec<usize>> {
    let items: Vec<String> = options.iter().map(|o| o.to_string()).collect();
    let result = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt(message)
        .items(&items)
        .defaults(defaults)
        .interact()?;
    Ok(result)
}

/// Display a section header in the TUI
pub fn section_header(title: &str) {
    println!();
    println!("{}", "─".repeat(60).dimmed());
    println!("{}", title.cyan().bold());
    println!("{}", "─".repeat(60).dimmed());
}

/// Display current value of a setting
pub fn show_current_value(setting: &str, value: &str) {
    println!("  {} {} = {}", "Current:".dimmed(), setting, value.yellow());
}

/// Display a success message
pub fn success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Display an info message
pub fn info(message: &str) {
    println!("{} {}", "→".cyan(), message);
}

/// Display a warning message
pub fn warning(message: &str) {
    println!("{} {}", "!".yellow().bold(), message);
}

/// Display an error message
pub fn error(message: &str) {
    println!("{} {}", "✗".red().bold(), message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_header() {
        // Just ensure it doesn't panic
        section_header("Test Section");
    }
}
