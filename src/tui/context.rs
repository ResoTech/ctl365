//! Run Context - Global Safety Framework
//!
//! Provides consistent handling of execution modes across CLI and TUI:
//! - DryRun: Preview changes without executing
//! - Plan: Generate and display execution plan
//! - Apply: Execute changes with confirmation
//!
//! Also handles confirmation policies and impact summaries.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global run context instance
static CONTEXT: OnceLock<RunContext> = OnceLock::new();

/// Execution mode for commands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunMode {
    /// Preview changes without executing
    DryRun,
    /// Generate and display execution plan
    Plan,
    /// Execute changes (default)
    #[default]
    Apply,
}

impl std::fmt::Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::DryRun => write!(f, "dry-run"),
            RunMode::Plan => write!(f, "plan"),
            RunMode::Apply => write!(f, "apply"),
        }
    }
}

impl std::str::FromStr for RunMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dry-run" | "dryrun" | "dry" => Ok(RunMode::DryRun),
            "plan" => Ok(RunMode::Plan),
            "apply" | "run" | "execute" => Ok(RunMode::Apply),
            _ => Err(format!("Unknown run mode: {}", s)),
        }
    }
}

/// Confirmation policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfirmPolicy {
    /// Always prompt for confirmation (default)
    #[default]
    Prompt,
    /// Auto-confirm (--yes flag)
    AutoYes,
    /// Auto-deny (--no flag)
    AutoNo,
}

/// Impact level for operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImpactLevel {
    /// Low impact - read-only or reversible
    Low,
    /// Medium impact - creates or modifies resources
    Medium,
    /// High impact - deletes resources or affects security
    High,
    /// Critical impact - tenant-wide or irreversible
    Critical,
}

impl std::fmt::Display for ImpactLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImpactLevel::Low => write!(f, "LOW"),
            ImpactLevel::Medium => write!(f, "MEDIUM"),
            ImpactLevel::High => write!(f, "HIGH"),
            ImpactLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Impact summary for an operation
#[derive(Debug, Clone)]
pub struct ImpactSummary {
    /// Operation name
    pub operation: String,
    /// Impact level
    pub level: ImpactLevel,
    /// Target tenant
    pub tenant: String,
    /// Resources to be created
    pub creates: Vec<String>,
    /// Resources to be modified
    pub modifies: Vec<String>,
    /// Resources to be deleted
    pub deletes: Vec<String>,
    /// Additional notes
    pub notes: Vec<String>,
}

impl ImpactSummary {
    pub fn new(operation: &str, level: ImpactLevel, tenant: &str) -> Self {
        Self {
            operation: operation.to_string(),
            level,
            tenant: tenant.to_string(),
            creates: Vec::new(),
            modifies: Vec::new(),
            deletes: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn create(mut self, resource: &str) -> Self {
        self.creates.push(resource.to_string());
        self
    }

    pub fn modify(mut self, resource: &str) -> Self {
        self.modifies.push(resource.to_string());
        self
    }

    pub fn delete(mut self, resource: &str) -> Self {
        self.deletes.push(resource.to_string());
        self
    }

    pub fn note(mut self, note: &str) -> Self {
        self.notes.push(note.to_string());
        self
    }

    /// Format as a display string
    pub fn format(&self) -> String {
        let mut lines = Vec::new();

        lines.push(format!("Operation: {}", self.operation));
        lines.push(format!("Tenant: {}", self.tenant));
        lines.push(format!("Impact: {}", self.level));
        lines.push(String::new());

        if !self.creates.is_empty() {
            lines.push(format!("CREATE ({}):", self.creates.len()));
            for r in &self.creates {
                lines.push(format!("  + {}", r));
            }
            lines.push(String::new());
        }

        if !self.modifies.is_empty() {
            lines.push(format!("MODIFY ({}):", self.modifies.len()));
            for r in &self.modifies {
                lines.push(format!("  ~ {}", r));
            }
            lines.push(String::new());
        }

        if !self.deletes.is_empty() {
            lines.push(format!("DELETE ({}):", self.deletes.len()));
            for r in &self.deletes {
                lines.push(format!("  - {}", r));
            }
            lines.push(String::new());
        }

        if !self.notes.is_empty() {
            lines.push("Notes:".to_string());
            for n in &self.notes {
                lines.push(format!("  * {}", n));
            }
        }

        lines.join("\n")
    }

    /// Format as markdown for TUI
    pub fn format_tui(&self) -> String {
        let mut lines = Vec::new();

        lines.push(format!("Impact: {} | Tenant: {}", self.level, self.tenant));

        let total = self.creates.len() + self.modifies.len() + self.deletes.len();
        if total > 0 {
            lines.push(format!(
                "\nChanges: {} create, {} modify, {} delete",
                self.creates.len(),
                self.modifies.len(),
                self.deletes.len()
            ));
        }

        if !self.creates.is_empty() && self.creates.len() <= 5 {
            lines.push("\nWill create:".to_string());
            for r in &self.creates {
                lines.push(format!("  + {}", r));
            }
        } else if !self.creates.is_empty() {
            lines.push(format!("\nWill create {} resources", self.creates.len()));
        }

        if !self.notes.is_empty() {
            for n in &self.notes {
                lines.push(format!("\n{}", n));
            }
        }

        lines.join("\n")
    }
}

/// Global run context
#[derive(Debug)]
pub struct RunContext {
    /// Current execution mode
    mode: std::sync::RwLock<RunMode>,
    /// Confirmation policy
    confirm_policy: std::sync::RwLock<ConfirmPolicy>,
    /// Verbose output
    verbose: AtomicBool,
    /// JSON output format
    json_output: AtomicBool,
}

impl Default for RunContext {
    fn default() -> Self {
        Self::new()
    }
}

impl RunContext {
    /// Create a new run context with defaults
    pub fn new() -> Self {
        Self {
            mode: std::sync::RwLock::new(RunMode::Apply),
            confirm_policy: std::sync::RwLock::new(ConfirmPolicy::Prompt),
            verbose: AtomicBool::new(false),
            json_output: AtomicBool::new(false),
        }
    }

    /// Initialize the global context
    pub fn init() -> &'static RunContext {
        CONTEXT.get_or_init(RunContext::new)
    }

    /// Get the global context
    pub fn global() -> &'static RunContext {
        CONTEXT.get_or_init(RunContext::new)
    }

    /// Set the run mode
    pub fn set_mode(&self, mode: RunMode) {
        if let Ok(mut m) = self.mode.write() {
            *m = mode;
        }
    }

    /// Get the current run mode
    pub fn mode(&self) -> RunMode {
        self.mode.read().map(|m| *m).unwrap_or(RunMode::Apply)
    }

    /// Check if in dry-run mode
    pub fn is_dry_run(&self) -> bool {
        self.mode() == RunMode::DryRun
    }

    /// Check if in plan mode
    pub fn is_plan(&self) -> bool {
        self.mode() == RunMode::Plan
    }

    /// Check if should execute (apply mode)
    pub fn should_execute(&self) -> bool {
        self.mode() == RunMode::Apply
    }

    /// Set confirmation policy
    pub fn set_confirm_policy(&self, policy: ConfirmPolicy) {
        if let Ok(mut p) = self.confirm_policy.write() {
            *p = policy;
        }
    }

    /// Get confirmation policy
    pub fn confirm_policy(&self) -> ConfirmPolicy {
        self.confirm_policy
            .read()
            .map(|p| *p)
            .unwrap_or(ConfirmPolicy::Prompt)
    }

    /// Check if should auto-confirm
    pub fn auto_confirm(&self) -> bool {
        self.confirm_policy() == ConfirmPolicy::AutoYes
    }

    /// Set verbose mode
    pub fn set_verbose(&self, verbose: bool) {
        self.verbose.store(verbose, Ordering::SeqCst);
    }

    /// Check if verbose
    pub fn is_verbose(&self) -> bool {
        self.verbose.load(Ordering::SeqCst)
    }

    /// Set JSON output mode
    pub fn set_json_output(&self, json: bool) {
        self.json_output.store(json, Ordering::SeqCst);
    }

    /// Check if JSON output
    pub fn is_json_output(&self) -> bool {
        self.json_output.load(Ordering::SeqCst)
    }

    /// Should prompt for confirmation given impact level
    pub fn should_confirm(&self, impact: ImpactLevel) -> bool {
        match self.confirm_policy() {
            ConfirmPolicy::AutoYes => false,
            ConfirmPolicy::AutoNo => true, // Will be rejected
            ConfirmPolicy::Prompt => {
                // Always confirm for high/critical, optionally for medium
                impact >= ImpactLevel::Medium
            }
        }
    }

    /// Check if operation would be blocked (auto-no + requires confirmation)
    pub fn would_block(&self, impact: ImpactLevel) -> bool {
        self.confirm_policy() == ConfirmPolicy::AutoNo && impact >= ImpactLevel::Medium
    }

    /// Format mode indicator for status bar
    pub fn mode_indicator(&self) -> String {
        match self.mode() {
            RunMode::DryRun => "[DRY-RUN]".to_string(),
            RunMode::Plan => "[PLAN]".to_string(),
            RunMode::Apply => String::new(),
        }
    }
}

/// Convenience functions for common impact summaries
impl ImpactSummary {
    /// Impact summary for baseline deployment
    pub fn baseline_deploy(name: &str, policy_count: usize, tenant: &str) -> Self {
        Self::new(
            &format!("Deploy {} Baseline", name),
            ImpactLevel::High,
            tenant,
        )
        .create(&format!("{} Intune policies", policy_count))
        .note("Policies will be created in Report-Only mode")
        .note("Review policy assignments after deployment")
    }

    /// Impact summary for CA deployment
    pub fn ca_deploy(policy_count: usize, tenant: &str) -> Self {
        Self::new(
            "Deploy Conditional Access Policies",
            ImpactLevel::Critical,
            tenant,
        )
        .create(&format!("{} CA policies", policy_count))
        .note("All policies start in Report-Only mode")
        .note("Review policies before enabling enforcement")
    }

    /// Impact summary for settings change
    pub fn settings_change(category: &str, setting_count: usize, tenant: &str) -> Self {
        Self::new(
            &format!("Apply {} Settings", category),
            ImpactLevel::Medium,
            tenant,
        )
        .modify(&format!("{} tenant settings", setting_count))
    }

    /// Impact summary for client deletion
    pub fn client_delete(name: &str) -> Self {
        Self::new("Delete Client", ImpactLevel::High, name)
            .delete(&format!("Client configuration: {}", name))
            .note("This does not affect the Azure AD app registration")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_mode_parse() {
        assert_eq!("dry-run".parse::<RunMode>().unwrap(), RunMode::DryRun);
        assert_eq!("plan".parse::<RunMode>().unwrap(), RunMode::Plan);
        assert_eq!("apply".parse::<RunMode>().unwrap(), RunMode::Apply);
    }

    #[test]
    fn test_impact_ordering() {
        assert!(ImpactLevel::Low < ImpactLevel::Medium);
        assert!(ImpactLevel::Medium < ImpactLevel::High);
        assert!(ImpactLevel::High < ImpactLevel::Critical);
    }

    #[test]
    fn test_context_defaults() {
        let ctx = RunContext::new();
        assert_eq!(ctx.mode(), RunMode::Apply);
        assert!(!ctx.is_dry_run());
        assert!(ctx.should_execute());
    }
}
