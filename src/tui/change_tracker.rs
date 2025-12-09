//! Audit Trail System for ctl365
//!
//! Comprehensive change tracking and audit logging for:
//! - All configuration changes made through the tool
//! - Policy deployments and modifications
//! - Authentication events
//! - Report generation
//!
//! Features:
//! - Persistent storage in JSON files (one per day)
//! - Session-based grouping
//! - Searchable history
//! - Export to various formats

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

lazy_static::lazy_static! {
    /// Global session changes tracker
    static ref SESSION_CHANGES: Mutex<Vec<AuditEntry>> = Mutex::new(Vec::new());
    /// Current session ID
    static ref SESSION_ID: Mutex<String> = Mutex::new(generate_session_id());
}

fn generate_session_id() -> String {
    format!("session-{}", chrono::Local::now().format("%Y%m%d-%H%M%S"))
}

/// Audit entry types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Setting was changed
    SettingChanged,
    /// Policy was created
    PolicyCreated,
    /// Policy was modified
    PolicyModified,
    /// Policy was deleted
    PolicyDeleted,
    /// Baseline was deployed
    BaselineDeployed,
    /// User authenticated
    UserAuthenticated,
    /// User logged out
    UserLoggedOut,
    /// Report was generated
    ReportGenerated,
    /// Export was created
    ExportCreated,
    /// Tenant was added
    TenantAdded,
    /// Tenant was removed
    TenantRemoved,
    /// Tenant was switched
    TenantSwitched,
    /// Error occurred
    Error,
    /// Info message
    Info,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::SettingChanged => "Setting Changed",
            AuditAction::PolicyCreated => "Policy Created",
            AuditAction::PolicyModified => "Policy Modified",
            AuditAction::PolicyDeleted => "Policy Deleted",
            AuditAction::BaselineDeployed => "Baseline Deployed",
            AuditAction::UserAuthenticated => "Authenticated",
            AuditAction::UserLoggedOut => "Logged Out",
            AuditAction::ReportGenerated => "Report Generated",
            AuditAction::ExportCreated => "Export Created",
            AuditAction::TenantAdded => "Tenant Added",
            AuditAction::TenantRemoved => "Tenant Removed",
            AuditAction::TenantSwitched => "Tenant Switched",
            AuditAction::Error => "Error",
            AuditAction::Info => "Info",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            AuditAction::SettingChanged => "⚙",
            AuditAction::PolicyCreated => "➕",
            AuditAction::PolicyModified => "✏",
            AuditAction::PolicyDeleted => "🗑",
            AuditAction::BaselineDeployed => "🚀",
            AuditAction::UserAuthenticated => "🔑",
            AuditAction::UserLoggedOut => "🚪",
            AuditAction::ReportGenerated => "📄",
            AuditAction::ExportCreated => "📦",
            AuditAction::TenantAdded => "🏢",
            AuditAction::TenantRemoved => "❌",
            AuditAction::TenantSwitched => "🔄",
            AuditAction::Error => "⚠",
            AuditAction::Info => "ℹ",
        }
    }
}

/// Severity level for audit entries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Success,
    Error,
}

/// A single audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: String,
    /// Session ID this entry belongs to
    pub session_id: String,
    /// Timestamp (ISO 8601)
    pub timestamp: String,
    /// Date only (for file grouping)
    pub date: String,
    /// Action type
    pub action: AuditAction,
    /// Severity level
    pub severity: AuditSeverity,
    /// Category (Defender, Exchange, CA, etc.)
    pub category: String,
    /// Target (policy name, setting name, etc.)
    pub target: String,
    /// Tenant name/abbreviation
    pub tenant: String,
    /// Previous value (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    /// New value (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
    /// Additional details/notes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// User who made the change (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Was this action successful?
    pub success: bool,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(action: AuditAction, category: &str, target: &str, tenant: &str) -> Self {
        let now = chrono::Local::now();
        let session_id = SESSION_ID.lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| generate_session_id());

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            session_id,
            timestamp: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            date: now.format("%Y-%m-%d").to_string(),
            action,
            severity: AuditSeverity::Info,
            category: category.to_string(),
            target: target.to_string(),
            tenant: tenant.to_string(),
            old_value: None,
            new_value: None,
            details: None,
            user: None,
            success: true,
            error_message: None,
        }
    }

    pub fn with_values(mut self, old: Option<&str>, new: Option<&str>) -> Self {
        self.old_value = old.map(|s| s.to_string());
        self.new_value = new.map(|s| s.to_string());
        self
    }

    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    pub fn with_severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_error(mut self, error: &str) -> Self {
        self.success = false;
        self.error_message = Some(error.to_string());
        self.severity = AuditSeverity::Error;
        self
    }

    pub fn success(mut self) -> Self {
        self.success = true;
        self.severity = AuditSeverity::Success;
        self
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Record an audit entry
pub fn record(entry: AuditEntry) {
    // Add to session
    if let Ok(mut changes) = SESSION_CHANGES.lock() {
        changes.push(entry.clone());
    }

    // Persist to file (async-friendly, fire-and-forget)
    let _ = persist_entry(&entry);
}

/// Record a setting change
pub fn record_setting_change(
    category: &str,
    setting: &str,
    old_value: Option<&str>,
    new_value: &str,
    tenant: &str,
) {
    let entry = AuditEntry::new(AuditAction::SettingChanged, category, setting, tenant)
        .with_values(old_value, Some(new_value))
        .with_severity(AuditSeverity::Success);
    record(entry);
}

/// Record a policy creation
pub fn record_policy_created(category: &str, policy_name: &str, tenant: &str) {
    let entry = AuditEntry::new(AuditAction::PolicyCreated, category, policy_name, tenant)
        .with_severity(AuditSeverity::Success);
    record(entry);
}

/// Record a policy deletion
pub fn record_policy_deleted(category: &str, policy_name: &str, tenant: &str) {
    let entry = AuditEntry::new(AuditAction::PolicyDeleted, category, policy_name, tenant)
        .with_severity(AuditSeverity::Warning);
    record(entry);
}

/// Record baseline deployment
pub fn record_baseline_deployed(baseline_name: &str, policy_count: usize, tenant: &str) {
    let entry = AuditEntry::new(AuditAction::BaselineDeployed, "Baseline", baseline_name, tenant)
        .with_details(&format!("Deployed {} policies", policy_count))
        .with_severity(AuditSeverity::Success);
    record(entry);
}

/// Record authentication
pub fn record_auth(tenant: &str, success: bool, error: Option<&str>) {
    let mut entry = AuditEntry::new(AuditAction::UserAuthenticated, "Auth", "Login", tenant);
    if success {
        entry = entry.success();
    } else if let Some(err) = error {
        entry = entry.with_error(err);
    }
    record(entry);
}

/// Record report generation
pub fn record_report_generated(report_type: &str, filename: &str, tenant: &str) {
    let entry = AuditEntry::new(AuditAction::ReportGenerated, "Reports", report_type, tenant)
        .with_details(&format!("Saved to: {}", filename))
        .with_severity(AuditSeverity::Success);
    record(entry);
}

/// Record tenant switch
pub fn record_tenant_switch(from: Option<&str>, to: &str) {
    let entry = AuditEntry::new(AuditAction::TenantSwitched, "Tenant", to, to)
        .with_values(from, Some(to))
        .with_severity(AuditSeverity::Info);
    record(entry);
}

/// Record an error
pub fn record_error(category: &str, target: &str, error: &str, tenant: &str) {
    let entry = AuditEntry::new(AuditAction::Error, category, target, tenant)
        .with_error(error);
    record(entry);
}

// =============================================================================
// Session Management
// =============================================================================

/// Get current session entries
pub fn get_session_entries() -> Vec<AuditEntry> {
    SESSION_CHANGES.lock()
        .map(|e| e.clone())
        .unwrap_or_default()
}

/// Get current session ID
pub fn get_session_id() -> String {
    SESSION_ID.lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| generate_session_id())
}

/// Clear current session
pub fn clear_session() {
    if let Ok(mut changes) = SESSION_CHANGES.lock() {
        changes.clear();
    }
}

/// Get session summary by category
pub fn get_session_summary() -> Vec<(String, usize)> {
    let entries = get_session_entries();
    let mut summary = std::collections::HashMap::new();

    for entry in entries {
        *summary.entry(entry.category).or_insert(0) += 1;
    }

    let mut result: Vec<_> = summary.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

// =============================================================================
// Persistence
// =============================================================================

fn get_audit_dir() -> Result<PathBuf> {
    let base = directories::ProjectDirs::from("com", "ctl365", "ctl365")
        .ok_or_else(|| crate::error::Error::ConfigError("Could not find config directory".into()))?;

    let audit_dir = base.config_dir().join("audit");
    std::fs::create_dir_all(&audit_dir)?;
    Ok(audit_dir)
}

fn get_audit_file(date: &str) -> Result<PathBuf> {
    let dir = get_audit_dir()?;
    Ok(dir.join(format!("audit-{}.json", date)))
}

fn persist_entry(entry: &AuditEntry) -> Result<()> {
    let filepath = get_audit_file(&entry.date)?;

    // Load existing entries for this day
    let mut entries = if filepath.exists() {
        let content = std::fs::read_to_string(&filepath)?;
        serde_json::from_str::<Vec<AuditEntry>>(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    entries.push(entry.clone());

    // Save back
    let content = serde_json::to_string_pretty(&entries)?;
    std::fs::write(&filepath, content)?;

    Ok(())
}

/// Load audit entries for a specific date
pub fn load_entries_for_date(date: &str) -> Result<Vec<AuditEntry>> {
    let filepath = get_audit_file(date)?;

    if !filepath.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&filepath)?;
    let entries: Vec<AuditEntry> = serde_json::from_str(&content)?;
    Ok(entries)
}

/// Load audit entries for date range
pub fn load_entries_range(start: &str, end: &str) -> Result<Vec<AuditEntry>> {
    let dir = get_audit_dir()?;
    let mut all_entries = Vec::new();

    if !dir.exists() {
        return Ok(all_entries);
    }

    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            if let Some(filename) = path.file_stem() {
                if let Some(filename_str) = filename.to_str() {
                    // Extract date from filename (audit-YYYY-MM-DD.json)
                    if let Some(date) = filename_str.strip_prefix("audit-") {
                        if date >= start && date <= end {
                            let content = std::fs::read_to_string(&path)?;
                            if let Ok(entries) = serde_json::from_str::<Vec<AuditEntry>>(&content) {
                                all_entries.extend(entries);
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort by timestamp descending (most recent first)
    all_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(all_entries)
}

/// Load recent audit entries (last N days)
pub fn load_recent_entries(days: u32) -> Result<Vec<AuditEntry>> {
    let end = chrono::Local::now().format("%Y-%m-%d").to_string();
    let start = (chrono::Local::now() - chrono::Duration::days(days as i64))
        .format("%Y-%m-%d")
        .to_string();

    load_entries_range(&start, &end)
}

/// Load all audit entries
pub fn load_all_entries() -> Result<Vec<AuditEntry>> {
    load_entries_range("2000-01-01", "2099-12-31")
}

/// Get list of available audit dates
pub fn get_audit_dates() -> Result<Vec<String>> {
    let dir = get_audit_dir()?;
    let mut dates = Vec::new();

    if !dir.exists() {
        return Ok(dates);
    }

    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            if let Some(filename) = path.file_stem() {
                if let Some(filename_str) = filename.to_str() {
                    if let Some(date) = filename_str.strip_prefix("audit-") {
                        dates.push(date.to_string());
                    }
                }
            }
        }
    }

    dates.sort_by(|a, b| b.cmp(a)); // Most recent first
    Ok(dates)
}

// =============================================================================
// Legacy compatibility
// =============================================================================

/// Legacy struct for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub timestamp: String,
    pub category: String,
    pub setting_name: String,
    pub change_type: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub changed_by: Option<String>,
    pub tenant: String,
    pub notes: Option<String>,
}

impl From<AuditEntry> for ConfigChange {
    fn from(entry: AuditEntry) -> Self {
        ConfigChange {
            timestamp: entry.timestamp,
            category: entry.category,
            setting_name: entry.target,
            change_type: entry.action.as_str().to_string(),
            old_value: entry.old_value,
            new_value: entry.new_value,
            changed_by: entry.user,
            tenant: entry.tenant,
            notes: entry.details,
        }
    }
}

/// Legacy function - loads from session
pub fn load_session_changes() -> Result<Vec<ConfigChange>> {
    Ok(get_session_entries().into_iter().map(|e| e.into()).collect())
}

/// Legacy function - get change summary
pub fn get_change_summary() -> Vec<(String, usize)> {
    get_session_summary()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_creation() {
        let entry = AuditEntry::new(
            AuditAction::SettingChanged,
            "Defender",
            "Safe Links",
            "RESO"
        )
        .with_values(Some("false"), Some("true"))
        .success();

        assert_eq!(entry.category, "Defender");
        assert_eq!(entry.target, "Safe Links");
        assert_eq!(entry.tenant, "RESO");
        assert!(entry.success);
    }

    #[test]
    fn test_session_tracking() {
        clear_session();

        record_setting_change("Test", "Setting1", None, "enabled", "TEST");
        record_setting_change("Test", "Setting2", Some("old"), "new", "TEST");

        let entries = get_session_entries();
        assert_eq!(entries.len(), 2);

        clear_session();
    }
}
