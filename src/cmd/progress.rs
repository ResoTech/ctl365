//! Progress bar and spinner utilities for CLI operations
//!
//! Provides consistent progress indicators across all commands.

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Create a spinner for indeterminate operations
pub fn create_spinner(message: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    let style = ProgressStyle::default_spinner()
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        .template("{spinner:.cyan} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner());
    spinner.set_style(style);
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner
}

/// Create a progress bar for determinate operations
pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    let bar = ProgressBar::new(total);
    let style = ProgressStyle::default_bar()
        .template("{spinner:.cyan} {msg} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("█▓▒░ ");
    bar.set_style(style);
    bar.set_message(message.to_string());
    bar
}

/// Create a progress bar for download-style operations (shows bytes)
pub fn create_download_bar(total: u64, message: &str) -> ProgressBar {
    let bar = ProgressBar::new(total);
    let style = ProgressStyle::default_bar()
        .template(
            "{spinner:.cyan} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec})",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("█▓▒░ ");
    bar.set_style(style);
    bar.set_message(message.to_string());
    bar
}

/// Create a multi-progress container for parallel operations
pub fn create_multi_progress() -> indicatif::MultiProgress {
    indicatif::MultiProgress::new()
}

/// Helper to finish a spinner with a success message
pub fn finish_spinner_success(spinner: &ProgressBar, message: &str) {
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{prefix:.green} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    spinner.set_prefix("✓");
    spinner.finish_with_message(message.to_string());
}

/// Helper to finish a spinner with an error message
pub fn finish_spinner_error(spinner: &ProgressBar, message: &str) {
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{prefix:.red} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    spinner.set_prefix("✗");
    spinner.finish_with_message(message.to_string());
}

/// Helper to finish a progress bar with a success message
pub fn finish_progress_success(bar: &ProgressBar, message: &str) {
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{prefix:.green} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    bar.set_prefix("✓");
    bar.finish_with_message(message.to_string());
}

/// Helper to finish a progress bar with an error message
pub fn finish_progress_error(bar: &ProgressBar, message: &str) {
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{prefix:.red} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    bar.set_prefix("✗");
    bar.finish_with_message(message.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_spinner() {
        let spinner = create_spinner("Testing...");
        assert!(!spinner.is_finished());
        spinner.finish();
        assert!(spinner.is_finished());
    }

    #[test]
    fn test_create_progress_bar() {
        let bar = create_progress_bar(100, "Processing");
        assert_eq!(bar.length(), Some(100));
        bar.inc(50);
        assert_eq!(bar.position(), 50);
        bar.finish();
    }

    #[test]
    fn test_finish_helpers() {
        let spinner = create_spinner("Working...");
        finish_spinner_success(&spinner, "Done");
        assert!(spinner.is_finished());

        let bar = create_progress_bar(10, "Tasks");
        finish_progress_error(&bar, "Failed");
        assert!(bar.is_finished());
    }
}
