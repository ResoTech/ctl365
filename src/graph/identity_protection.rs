//! Entra ID Identity Protection & Audit Logs
//!
//! Provides access to:
//! - Sign-in logs (requires Azure AD Premium P1/P2)
//! - Risky sign-ins (requires Azure AD Premium P2)
//! - Risky users (requires Azure AD Premium P2)
//! - Directory audit logs (requires Azure AD Premium P1/P2)
//!
//! Required permissions:
//! - AuditLog.Read.All - For sign-in and directory audit logs
//! - IdentityRiskyUser.Read.All - For risky users (read-only)
//! - IdentityRiskyUser.ReadWrite.All - For risky user actions (dismiss/confirm)
//! - IdentityRiskEvent.Read.All - For risky sign-ins

use crate::error::Result;
use crate::graph::GraphClient;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// Sign-in Logs (auditLogs/signIns)
// ============================================================================

/// Sign-in log entry from Entra ID
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInLog {
    pub id: String,
    pub created_date_time: DateTime<Utc>,
    pub user_display_name: Option<String>,
    pub user_principal_name: Option<String>,
    pub user_id: Option<String>,
    pub app_display_name: Option<String>,
    pub app_id: Option<String>,
    pub ip_address: Option<String>,
    pub client_app_used: Option<String>,
    pub conditional_access_status: Option<String>,
    pub is_interactive: Option<bool>,
    #[serde(default)]
    pub risk_detail: Option<String>,
    #[serde(default)]
    pub risk_level_aggregated: Option<String>,
    #[serde(default)]
    pub risk_level_during_sign_in: Option<String>,
    #[serde(default)]
    pub risk_state: Option<String>,
    pub status: Option<SignInStatus>,
    pub device_detail: Option<DeviceDetail>,
    pub location: Option<SignInLocation>,
    #[serde(default)]
    pub mfa_detail: Option<MfaDetail>,
    #[serde(default)]
    pub resource_display_name: Option<String>,
    #[serde(default)]
    pub resource_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInStatus {
    pub error_code: Option<i32>,
    pub failure_reason: Option<String>,
    pub additional_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDetail {
    pub device_id: Option<String>,
    pub display_name: Option<String>,
    pub operating_system: Option<String>,
    pub browser: Option<String>,
    pub is_compliant: Option<bool>,
    pub is_managed: Option<bool>,
    pub trust_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInLocation {
    pub city: Option<String>,
    pub state: Option<String>,
    pub country_or_region: Option<String>,
    pub geo_coordinates: Option<GeoCoordinates>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoCoordinates {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaDetail {
    pub mfa_auth_method: Option<String>,
    pub mfa_auth_detail: Option<String>,
}

// ============================================================================
// Risky Users (identityProtection/riskyUsers)
// ============================================================================

/// Risky user from Identity Protection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskyUser {
    pub id: String,
    pub user_display_name: Option<String>,
    pub user_principal_name: Option<String>,
    pub risk_level: Option<RiskLevel>,
    pub risk_state: Option<RiskState>,
    pub risk_detail: Option<String>,
    pub risk_last_updated_date_time: Option<DateTime<Utc>>,
    pub is_deleted: Option<bool>,
    pub is_processing: Option<bool>,
    #[serde(default)]
    pub history: Vec<RiskyUserHistoryItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskyUserHistoryItem {
    pub id: String,
    pub user_id: Option<String>,
    pub initiated_by: Option<String>,
    pub activity: Option<RiskUserActivity>,
    pub risk_level: Option<RiskLevel>,
    pub risk_state: Option<RiskState>,
    pub risk_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskUserActivity {
    pub detail: Option<String>,
    #[serde(rename = "riskEventTypes")]
    pub risk_event_types: Option<Vec<String>>,
}

// ============================================================================
// Risky Sign-ins (identityProtection/riskySignIns) - Beta API
// ============================================================================

/// Risky sign-in from Identity Protection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskySignIn {
    pub id: String,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
    pub risk_level: Option<RiskLevel>,
    pub risk_state: Option<RiskState>,
    pub risk_detail: Option<String>,
    pub risk_event_types: Option<Vec<String>>,
    #[serde(rename = "riskEventTypes_v2")]
    pub risk_event_types_v2: Option<Vec<String>>,
    pub user_id: Option<String>,
    pub user_display_name: Option<String>,
    pub user_principal_name: Option<String>,
    pub created_date_time: Option<DateTime<Utc>>,
    pub ip_address: Option<String>,
    pub location: Option<SignInLocation>,
}

// ============================================================================
// Directory Audit Logs (auditLogs/directoryAudits)
// ============================================================================

/// Directory audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryAudit {
    pub id: String,
    pub activity_date_time: DateTime<Utc>,
    pub activity_display_name: String,
    pub category: String,
    pub correlation_id: Option<String>,
    pub logged_by_service: Option<String>,
    pub operation_type: Option<String>,
    pub result: Option<AuditResult>,
    pub result_reason: Option<String>,
    pub initiated_by: Option<AuditInitiator>,
    #[serde(default)]
    pub target_resources: Vec<AuditTargetResource>,
    #[serde(default)]
    pub additional_details: Vec<KeyValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditInitiator {
    pub user: Option<AuditUserIdentity>,
    pub app: Option<AuditAppIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditUserIdentity {
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub user_principal_name: Option<String>,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditAppIdentity {
    pub app_id: Option<String>,
    pub display_name: Option<String>,
    pub service_principal_id: Option<String>,
    pub service_principal_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditTargetResource {
    pub id: Option<String>,
    pub display_name: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    pub user_principal_name: Option<String>,
    #[serde(default)]
    pub modified_properties: Vec<ModifiedProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifiedProperty {
    pub display_name: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: Option<String>,
}

// ============================================================================
// Common Enums
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Hidden,
    #[serde(other)]
    Unknown,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::None => "None",
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Hidden => "Hidden",
            RiskLevel::Unknown => "Unknown",
        }
    }

    /// Color for TUI display (basic ANSI colors for Windows compatibility)
    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            RiskLevel::None => Color::Green,
            RiskLevel::Low => Color::Blue,
            RiskLevel::Medium => Color::Yellow,
            RiskLevel::High => Color::Red,
            RiskLevel::Hidden => Color::DarkGray,
            RiskLevel::Unknown => Color::DarkGray,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RiskState {
    None,
    ConfirmedSafe,
    Remediated,
    Dismissed,
    AtRisk,
    ConfirmedCompromised,
    #[serde(other)]
    Unknown,
}

impl RiskState {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskState::None => "None",
            RiskState::ConfirmedSafe => "Confirmed Safe",
            RiskState::Remediated => "Remediated",
            RiskState::Dismissed => "Dismissed",
            RiskState::AtRisk => "At Risk",
            RiskState::ConfirmedCompromised => "Confirmed Compromised",
            RiskState::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuditResult {
    Success,
    Failure,
    Timeout,
    #[serde(other)]
    Unknown,
}

// ============================================================================
// Filter Options
// ============================================================================

/// Filter options for sign-in logs
#[derive(Debug, Default, Clone)]
pub struct SignInFilter {
    /// Filter by user principal name (contains)
    pub user: Option<String>,
    /// Filter by application name (contains)
    pub app: Option<String>,
    /// Filter by status (success/failure)
    pub status: Option<SignInStatusFilter>,
    /// Filter by risk level
    pub risk_level: Option<RiskLevel>,
    /// Maximum number of results
    pub top: Option<u32>,
    /// Date filter (created after)
    pub created_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy)]
pub enum SignInStatusFilter {
    Success,
    Failure,
}

impl SignInFilter {
    pub fn to_query_string(&self) -> String {
        let mut filters: Vec<String> = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if let Some(ref user) = self.user {
            filters.push(format!("contains(userPrincipalName, '{}')", user));
        }

        if let Some(ref app) = self.app {
            filters.push(format!("contains(appDisplayName, '{}')", app));
        }

        if let Some(status) = &self.status {
            match status {
                SignInStatusFilter::Success => filters.push("status/errorCode eq 0".to_string()),
                SignInStatusFilter::Failure => filters.push("status/errorCode ne 0".to_string()),
            }
        }

        if let Some(risk) = &self.risk_level {
            let risk_str = match risk {
                RiskLevel::None => "none",
                RiskLevel::Low => "low",
                RiskLevel::Medium => "medium",
                RiskLevel::High => "high",
                _ => "none",
            };
            filters.push(format!("riskLevelDuringSignIn eq '{}'", risk_str));
        }

        if let Some(date) = &self.created_after {
            filters.push(format!(
                "createdDateTime ge {}",
                date.format("%Y-%m-%dT%H:%M:%SZ")
            ));
        }

        if !filters.is_empty() {
            params.push(format!("$filter={}", filters.join(" and ")));
        }

        if let Some(top) = self.top {
            params.push(format!("$top={}", top));
        }

        // Always order by newest first
        params.push("$orderby=createdDateTime desc".to_string());

        if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        }
    }
}

/// Filter options for risky users
#[derive(Debug, Default, Clone)]
pub struct RiskyUserFilter {
    pub risk_level: Option<RiskLevel>,
    pub risk_state: Option<RiskState>,
    pub top: Option<u32>,
}

impl RiskyUserFilter {
    pub fn to_query_string(&self) -> String {
        let mut filters: Vec<String> = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if let Some(level) = &self.risk_level {
            let level_str = match level {
                RiskLevel::Low => "low",
                RiskLevel::Medium => "medium",
                RiskLevel::High => "high",
                _ => return String::new(),
            };
            filters.push(format!("riskLevel eq '{}'", level_str));
        }

        if let Some(state) = &self.risk_state {
            let state_str = match state {
                RiskState::AtRisk => "atRisk",
                RiskState::ConfirmedCompromised => "confirmedCompromised",
                RiskState::Remediated => "remediated",
                RiskState::Dismissed => "dismissed",
                RiskState::ConfirmedSafe => "confirmedSafe",
                _ => return String::new(),
            };
            filters.push(format!("riskState eq '{}'", state_str));
        }

        if !filters.is_empty() {
            params.push(format!("$filter={}", filters.join(" and ")));
        }

        if let Some(top) = self.top {
            params.push(format!("$top={}", top));
        }

        if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        }
    }
}

/// Filter options for directory audits
#[derive(Debug, Default, Clone)]
pub struct DirectoryAuditFilter {
    pub category: Option<String>,
    pub initiated_by_user: Option<String>,
    pub target_resource: Option<String>,
    pub activity_after: Option<DateTime<Utc>>,
    pub top: Option<u32>,
}

impl DirectoryAuditFilter {
    pub fn to_query_string(&self) -> String {
        let mut filters: Vec<String> = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if let Some(ref cat) = self.category {
            filters.push(format!("category eq '{}'", cat));
        }

        if let Some(ref user) = self.initiated_by_user {
            filters.push(format!(
                "contains(initiatedBy/user/userPrincipalName, '{}')",
                user
            ));
        }

        if let Some(date) = &self.activity_after {
            filters.push(format!(
                "activityDateTime ge {}",
                date.format("%Y-%m-%dT%H:%M:%SZ")
            ));
        }

        if !filters.is_empty() {
            params.push(format!("$filter={}", filters.join(" and ")));
        }

        if let Some(top) = self.top {
            params.push(format!("$top={}", top));
        }

        params.push("$orderby=activityDateTime desc".to_string());

        if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        }
    }
}

// ============================================================================
// API Functions
// ============================================================================

/// Get sign-in logs with optional filtering
pub async fn get_sign_in_logs(
    client: &GraphClient,
    filter: Option<SignInFilter>,
) -> Result<Vec<SignInLog>> {
    let query = filter.map(|f| f.to_query_string()).unwrap_or_default();
    let endpoint = format!("auditLogs/signIns{}", query);
    client.get_all_pages(&endpoint).await
}

/// Get a limited number of recent sign-ins (for TUI display)
pub async fn get_recent_sign_ins(client: &GraphClient, limit: u32) -> Result<Vec<SignInLog>> {
    let filter = SignInFilter {
        top: Some(limit),
        ..Default::default()
    };
    get_sign_in_logs(client, Some(filter)).await
}

/// Get failed sign-ins
pub async fn get_failed_sign_ins(client: &GraphClient, limit: u32) -> Result<Vec<SignInLog>> {
    let filter = SignInFilter {
        status: Some(SignInStatusFilter::Failure),
        top: Some(limit),
        ..Default::default()
    };
    get_sign_in_logs(client, Some(filter)).await
}

/// Get risky sign-ins (requires P2 license, uses beta API)
pub async fn get_risky_sign_ins(
    client: &GraphClient,
    limit: Option<u32>,
) -> Result<Vec<RiskySignIn>> {
    let query = limit
        .map(|l| format!("?$top={}&$orderby=createdDateTime desc", l))
        .unwrap_or_default();
    let endpoint = format!("identityProtection/riskySignIns{}", query);
    client.get_all_pages_beta(&endpoint).await
}

/// Get risky users with optional filtering
pub async fn get_risky_users(
    client: &GraphClient,
    filter: Option<RiskyUserFilter>,
) -> Result<Vec<RiskyUser>> {
    let query = filter.map(|f| f.to_query_string()).unwrap_or_default();
    let endpoint = format!("identityProtection/riskyUsers{}", query);
    client.get_all_pages(&endpoint).await
}

/// Get users currently at risk (convenience function)
pub async fn get_users_at_risk(client: &GraphClient) -> Result<Vec<RiskyUser>> {
    let filter = RiskyUserFilter {
        risk_state: Some(RiskState::AtRisk),
        ..Default::default()
    };
    get_risky_users(client, Some(filter)).await
}

/// Get high-risk users
pub async fn get_high_risk_users(client: &GraphClient) -> Result<Vec<RiskyUser>> {
    let filter = RiskyUserFilter {
        risk_level: Some(RiskLevel::High),
        ..Default::default()
    };
    get_risky_users(client, Some(filter)).await
}

/// Dismiss a risky user (requires IdentityRiskyUser.ReadWrite.All)
pub async fn dismiss_risky_user(client: &GraphClient, user_ids: &[&str]) -> Result<()> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DismissRequest {
        user_ids: Vec<String>,
    }

    let request = DismissRequest {
        user_ids: user_ids.iter().map(|s| s.to_string()).collect(),
    };

    // POST returns 204 No Content on success
    let _: serde_json::Value = client
        .post("identityProtection/riskyUsers/dismiss", &request)
        .await?;
    Ok(())
}

/// Confirm a user as compromised (requires IdentityRiskyUser.ReadWrite.All)
pub async fn confirm_user_compromised(client: &GraphClient, user_ids: &[&str]) -> Result<()> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ConfirmRequest {
        user_ids: Vec<String>,
    }

    let request = ConfirmRequest {
        user_ids: user_ids.iter().map(|s| s.to_string()).collect(),
    };

    let _: serde_json::Value = client
        .post("identityProtection/riskyUsers/confirmCompromised", &request)
        .await?;
    Ok(())
}

/// Get risky user history
pub async fn get_risky_user_history(
    client: &GraphClient,
    user_id: &str,
) -> Result<Vec<RiskyUserHistoryItem>> {
    let endpoint = format!("identityProtection/riskyUsers/{}/history", user_id);
    client.get_all_pages(&endpoint).await
}

/// Get directory audit logs with optional filtering
pub async fn get_directory_audits(
    client: &GraphClient,
    filter: Option<DirectoryAuditFilter>,
) -> Result<Vec<DirectoryAudit>> {
    let query = filter.map(|f| f.to_query_string()).unwrap_or_default();
    let endpoint = format!("auditLogs/directoryAudits{}", query);
    client.get_all_pages(&endpoint).await
}

/// Get recent directory audits (for TUI display)
pub async fn get_recent_directory_audits(
    client: &GraphClient,
    limit: u32,
) -> Result<Vec<DirectoryAudit>> {
    let filter = DirectoryAuditFilter {
        top: Some(limit),
        ..Default::default()
    };
    get_directory_audits(client, Some(filter)).await
}

/// Get directory audits by category
pub async fn get_directory_audits_by_category(
    client: &GraphClient,
    category: &str,
    limit: u32,
) -> Result<Vec<DirectoryAudit>> {
    let filter = DirectoryAuditFilter {
        category: Some(category.to_string()),
        top: Some(limit),
        ..Default::default()
    };
    get_directory_audits(client, Some(filter)).await
}

// ============================================================================
// Summary Types (for TUI dashboard)
// ============================================================================

/// Summary of Identity Protection status
#[derive(Debug, Default)]
pub struct IdentityProtectionSummary {
    pub total_risky_users: usize,
    pub high_risk_users: usize,
    pub medium_risk_users: usize,
    pub low_risk_users: usize,
    pub recent_risky_sign_ins: usize,
    pub failed_sign_ins_24h: usize,
}

/// Get a summary of Identity Protection status
pub async fn get_identity_protection_summary(
    client: &GraphClient,
) -> Result<IdentityProtectionSummary> {
    // Get risky users by level
    let risky_users = get_risky_users(client, None).await.unwrap_or_default();

    let high_risk = risky_users
        .iter()
        .filter(|u| matches!(u.risk_level, Some(RiskLevel::High)))
        .count();
    let medium_risk = risky_users
        .iter()
        .filter(|u| matches!(u.risk_level, Some(RiskLevel::Medium)))
        .count();
    let low_risk = risky_users
        .iter()
        .filter(|u| matches!(u.risk_level, Some(RiskLevel::Low)))
        .count();

    // Get risky sign-ins (may fail if no P2 license)
    let risky_sign_ins = get_risky_sign_ins(client, Some(100))
        .await
        .unwrap_or_default();

    // Get failed sign-ins in last 24h
    let yesterday = Utc::now() - chrono::Duration::hours(24);
    let failed_filter = SignInFilter {
        status: Some(SignInStatusFilter::Failure),
        created_after: Some(yesterday),
        top: Some(1000),
        ..Default::default()
    };
    let failed_sign_ins = get_sign_in_logs(client, Some(failed_filter))
        .await
        .unwrap_or_default();

    Ok(IdentityProtectionSummary {
        total_risky_users: risky_users.len(),
        high_risk_users: high_risk,
        medium_risk_users: medium_risk,
        low_risk_users: low_risk,
        recent_risky_sign_ins: risky_sign_ins.len(),
        failed_sign_ins_24h: failed_sign_ins.len(),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::High.as_str(), "High");
        assert_eq!(RiskLevel::Medium.as_str(), "Medium");
        assert_eq!(RiskLevel::Low.as_str(), "Low");
        assert_eq!(RiskLevel::None.as_str(), "None");
    }

    #[test]
    fn test_risk_state_display() {
        assert_eq!(RiskState::AtRisk.as_str(), "At Risk");
        assert_eq!(
            RiskState::ConfirmedCompromised.as_str(),
            "Confirmed Compromised"
        );
        assert_eq!(RiskState::Dismissed.as_str(), "Dismissed");
    }

    #[test]
    fn test_sign_in_filter_query_string() {
        let filter = SignInFilter {
            user: Some("user@example.com".to_string()),
            top: Some(50),
            ..Default::default()
        };
        let query = filter.to_query_string();
        assert!(query.contains("userPrincipalName"));
        assert!(query.contains("$top=50"));
    }

    #[test]
    fn test_sign_in_filter_status() {
        let filter = SignInFilter {
            status: Some(SignInStatusFilter::Failure),
            ..Default::default()
        };
        let query = filter.to_query_string();
        assert!(query.contains("errorCode ne 0"));
    }

    #[test]
    fn test_risky_user_filter_query_string() {
        let filter = RiskyUserFilter {
            risk_level: Some(RiskLevel::High),
            risk_state: Some(RiskState::AtRisk),
            top: Some(25),
        };
        let query = filter.to_query_string();
        assert!(query.contains("riskLevel eq 'high'"));
        assert!(query.contains("riskState eq 'atRisk'"));
        assert!(query.contains("$top=25"));
    }

    #[test]
    fn test_directory_audit_filter_query_string() {
        let filter = DirectoryAuditFilter {
            category: Some("UserManagement".to_string()),
            top: Some(100),
            ..Default::default()
        };
        let query = filter.to_query_string();
        assert!(query.contains("category eq 'UserManagement'"));
        assert!(query.contains("$top=100"));
    }

    #[test]
    fn test_empty_filter_returns_empty_string_prefix() {
        let filter = SignInFilter::default();
        let query = filter.to_query_string();
        // Should still have orderby
        assert!(query.contains("$orderby"));
    }
}
