//! Async Task Manager for TUI
//!
//! Provides non-blocking execution of Graph API calls and other async operations.
//! Uses channels to communicate between the async runtime and the TUI main loop.
//!
//! Architecture:
//! - TUI main loop runs on the main thread (synchronous)
//! - Async tasks run on a background tokio runtime
//! - Communication via crossbeam channels (thread-safe, non-blocking)

use crate::config::ConfigManager;
use crate::error::Result;
use crossbeam_channel::{Receiver, Sender, bounded};
use std::sync::Arc;
use std::thread;

/// Messages sent from TUI to the task worker
#[derive(Debug, Clone)]
pub enum TaskRequest {
    /// Load policies from Graph API
    LoadPolicies {
        tenant_name: String,
        policy_type: PolicyType,
    },
    /// Deploy a baseline
    DeployBaseline {
        tenant_name: String,
        baseline_type: String,
        baseline_data: serde_json::Value,
    },
    /// Deploy CA policies
    DeployConditionalAccess { tenant_name: String },
    /// Apply settings to tenant
    ApplySettings {
        tenant_name: String,
        category: SettingsCategory,
        settings: std::collections::HashMap<String, bool>,
    },
    /// Test authentication
    TestAuth { tenant_name: String },
    /// Shutdown the worker
    Shutdown,
}

/// Policy types for loading
#[derive(Debug, Clone)]
pub enum PolicyType {
    Compliance,
    Configuration,
    SettingsCatalog,
    ConditionalAccess,
    Apps,
    All,
}

/// Settings categories
#[derive(Debug, Clone)]
pub enum SettingsCategory {
    Defender,
    Exchange,
    SharePoint,
    Teams,
    All,
}

/// Progress update from worker to TUI
#[derive(Debug, Clone)]
pub struct TaskProgress {
    pub task_id: String,
    pub percent: u16,
    pub message: String,
    pub phase: String,
}

/// Result of a completed task
#[derive(Debug, Clone)]
pub enum TaskResult {
    /// Policies loaded successfully
    PoliciesLoaded { policies: Vec<PolicyData> },
    /// Baseline deployed
    BaselineDeployed { count: usize, message: String },
    /// CA policies deployed
    CaDeployed { count: usize, message: String },
    /// Settings applied
    SettingsApplied { message: String },
    /// Auth test result
    AuthResult { success: bool, message: String },
    /// Task failed
    Error { message: String },
}

/// Policy data returned from Graph
#[derive(Debug, Clone)]
pub struct PolicyData {
    pub name: String,
    pub policy_type: String,
    pub status: String,
    pub platform: String,
    pub assignments: usize,
    pub last_modified: String,
}

/// Messages sent from worker to TUI
#[derive(Debug, Clone)]
pub enum TaskResponse {
    /// Progress update
    Progress(TaskProgress),
    /// Task completed
    Completed { task_id: String, result: TaskResult },
    /// Worker is ready
    Ready,
}

/// Handle for sending tasks to the worker
pub struct TaskSender {
    tx: Sender<TaskRequest>,
}

impl TaskSender {
    pub fn send(
        &self,
        request: TaskRequest,
    ) -> std::result::Result<(), crossbeam_channel::SendError<TaskRequest>> {
        self.tx.send(request)
    }

    pub fn shutdown(&self) {
        let _ = self.tx.send(TaskRequest::Shutdown);
    }
}

/// Handle for receiving responses from the worker
pub struct TaskReceiver {
    rx: Receiver<TaskResponse>,
}

impl TaskReceiver {
    /// Try to receive a response without blocking
    pub fn try_recv(&self) -> Option<TaskResponse> {
        self.rx.try_recv().ok()
    }

    /// Drain all available responses
    pub fn drain(&self) -> Vec<TaskResponse> {
        let mut responses = Vec::new();
        while let Some(resp) = self.try_recv() {
            responses.push(resp);
        }
        responses
    }
}

/// Spawn the background task worker
/// Returns handles for sending requests and receiving responses
pub fn spawn_task_worker(config: ConfigManager) -> (TaskSender, TaskReceiver) {
    let (request_tx, request_rx) = bounded::<TaskRequest>(32);
    let (response_tx, response_rx) = bounded::<TaskResponse>(64);

    let config = Arc::new(config);

    thread::spawn(move || {
        // Create a new tokio runtime for this thread
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => {
                // Cannot report error - worker thread will simply not respond
                // The TUI will show no data which indicates a problem
                return;
            }
        };

        rt.block_on(async move {
            // Signal that worker is ready
            let _ = response_tx.send(TaskResponse::Ready);

            while let Ok(request) = request_rx.recv() {
                match request {
                    TaskRequest::Shutdown => {
                        break;
                    }
                    TaskRequest::LoadPolicies {
                        tenant_name,
                        policy_type,
                    } => {
                        let task_id =
                            format!("load_policies_{}", chrono::Utc::now().timestamp_millis());
                        let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
                            task_id: task_id.clone(),
                            percent: 0,
                            message: "Connecting to Graph API...".into(),
                            phase: "init".into(),
                        }));

                        let result = load_policies_async(
                            &config,
                            &tenant_name,
                            &policy_type,
                            &response_tx,
                            &task_id,
                        )
                        .await;
                        let _ = response_tx.send(TaskResponse::Completed { task_id, result });
                    }
                    TaskRequest::DeployBaseline {
                        tenant_name,
                        baseline_type,
                        baseline_data,
                    } => {
                        let task_id =
                            format!("deploy_baseline_{}", chrono::Utc::now().timestamp_millis());
                        let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
                            task_id: task_id.clone(),
                            percent: 0,
                            message: format!("Preparing {} baseline...", baseline_type),
                            phase: "init".into(),
                        }));

                        let result = deploy_baseline_async(
                            &config,
                            &tenant_name,
                            &baseline_type,
                            &baseline_data,
                            &response_tx,
                            &task_id,
                        )
                        .await;
                        let _ = response_tx.send(TaskResponse::Completed { task_id, result });
                    }
                    TaskRequest::DeployConditionalAccess { tenant_name } => {
                        let task_id =
                            format!("deploy_ca_{}", chrono::Utc::now().timestamp_millis());
                        let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
                            task_id: task_id.clone(),
                            percent: 0,
                            message: "Generating CA policies...".into(),
                            phase: "init".into(),
                        }));

                        let result =
                            deploy_ca_async(&config, &tenant_name, &response_tx, &task_id).await;
                        let _ = response_tx.send(TaskResponse::Completed { task_id, result });
                    }
                    TaskRequest::ApplySettings {
                        tenant_name,
                        category,
                        settings,
                    } => {
                        let task_id =
                            format!("apply_settings_{}", chrono::Utc::now().timestamp_millis());
                        let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
                            task_id: task_id.clone(),
                            percent: 0,
                            message: "Applying settings...".into(),
                            phase: "init".into(),
                        }));

                        let result = apply_settings_async(
                            &config,
                            &tenant_name,
                            &category,
                            &settings,
                            &response_tx,
                            &task_id,
                        )
                        .await;
                        let _ = response_tx.send(TaskResponse::Completed { task_id, result });
                    }
                    TaskRequest::TestAuth { tenant_name } => {
                        let task_id =
                            format!("test_auth_{}", chrono::Utc::now().timestamp_millis());
                        let result = test_auth_async(&config, &tenant_name).await;
                        let _ = response_tx.send(TaskResponse::Completed { task_id, result });
                    }
                }
            }
        });
    });

    (
        TaskSender { tx: request_tx },
        TaskReceiver { rx: response_rx },
    )
}

// ============================================================================
// Async Task Implementations
// ============================================================================

async fn load_policies_async(
    config: &ConfigManager,
    tenant_name: &str,
    policy_type: &PolicyType,
    response_tx: &Sender<TaskResponse>,
    task_id: &str,
) -> TaskResult {
    use crate::graph::GraphClient;

    // Get Graph client
    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 10,
        message: "Authenticating...".into(),
        phase: "auth".into(),
    }));

    let client = match GraphClient::from_config(config, tenant_name).await {
        Ok(c) => c,
        Err(e) => {
            return TaskResult::Error {
                message: format!("Authentication failed: {}", e),
            };
        }
    };

    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 30,
        message: "Fetching policies...".into(),
        phase: "fetch".into(),
    }));

    // Fetch policies based on type
    let policies = match policy_type {
        PolicyType::ConditionalAccess => fetch_ca_policies(&client).await,
        PolicyType::Compliance => fetch_compliance_policies(&client).await,
        PolicyType::Configuration | PolicyType::SettingsCatalog => {
            fetch_config_policies(&client).await
        }
        PolicyType::Apps => fetch_app_policies(&client).await,
        PolicyType::All => fetch_all_policies(&client).await,
    };

    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 100,
        message: "Complete".into(),
        phase: "done".into(),
    }));

    match policies {
        Ok(p) => TaskResult::PoliciesLoaded { policies: p },
        Err(e) => TaskResult::Error {
            message: e.to_string(),
        },
    }
}

async fn fetch_ca_policies(client: &crate::graph::GraphClient) -> Result<Vec<PolicyData>> {
    #[derive(serde::Deserialize)]
    struct CaResponse {
        value: Vec<CaPolicy>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CaPolicy {
        id: String,
        display_name: String,
        state: String,
        #[serde(default)]
        modified_date_time: Option<String>,
    }

    let response: CaResponse = client.get("identity/conditionalAccess/policies").await?;

    Ok(response
        .value
        .into_iter()
        .map(|p| PolicyData {
            name: p.display_name,
            policy_type: "Conditional Access".into(),
            status: match p.state.as_str() {
                "enabled" => "Deployed",
                "enabledForReportingButNotEnforced" => "Report-Only",
                "disabled" => "Disabled",
                _ => "Unknown",
            }
            .into(),
            platform: "All".into(),
            assignments: 0, // Would need additional API call
            last_modified: p.modified_date_time.unwrap_or_else(|| "-".into()),
        })
        .collect())
}

async fn fetch_compliance_policies(client: &crate::graph::GraphClient) -> Result<Vec<PolicyData>> {
    #[derive(serde::Deserialize)]
    struct ComplianceResponse {
        value: Vec<CompliancePolicy>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CompliancePolicy {
        #[allow(dead_code)]
        id: String,
        display_name: String,
        #[serde(default)]
        last_modified_date_time: Option<String>,
    }

    let response: ComplianceResponse = client
        .get_beta("deviceManagement/deviceCompliancePolicies")
        .await?;

    Ok(response
        .value
        .into_iter()
        .map(|p| PolicyData {
            name: p.display_name,
            policy_type: "Compliance".into(),
            status: "Deployed".into(),
            platform: "Windows".into(), // Would need to parse from policy
            assignments: 0,
            last_modified: p.last_modified_date_time.unwrap_or_else(|| "-".into()),
        })
        .collect())
}

async fn fetch_config_policies(client: &crate::graph::GraphClient) -> Result<Vec<PolicyData>> {
    #[derive(serde::Deserialize)]
    struct ConfigResponse {
        value: Vec<ConfigPolicy>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConfigPolicy {
        #[allow(dead_code)]
        id: String,
        name: String,
        #[serde(default)]
        last_modified_date_time: Option<String>,
    }

    let response: ConfigResponse = client
        .get_beta("deviceManagement/configurationPolicies")
        .await?;

    Ok(response
        .value
        .into_iter()
        .map(|p| PolicyData {
            name: p.name,
            policy_type: "Settings Catalog".into(),
            status: "Deployed".into(),
            platform: "Windows".into(),
            assignments: 0,
            last_modified: p.last_modified_date_time.unwrap_or_else(|| "-".into()),
        })
        .collect())
}

async fn fetch_app_policies(client: &crate::graph::GraphClient) -> Result<Vec<PolicyData>> {
    #[derive(serde::Deserialize)]
    struct AppResponse {
        value: Vec<App>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct App {
        #[allow(dead_code)]
        id: String,
        display_name: String,
        #[serde(default, rename = "@odata.type")]
        odata_type: Option<String>,
        #[serde(default)]
        last_modified_date_time: Option<String>,
    }

    let response: AppResponse = client
        .get_beta("deviceAppManagement/mobileApps?$top=50")
        .await?;

    Ok(response
        .value
        .into_iter()
        .map(|a| {
            let app_type = a
                .odata_type
                .as_deref()
                .map(|t| t.replace("#microsoft.graph.", "").replace("App", ""))
                .unwrap_or_else(|| "Unknown".into());
            PolicyData {
                name: a.display_name,
                policy_type: app_type,
                status: "Deployed".into(),
                platform: "Windows".into(),
                assignments: 0,
                last_modified: a.last_modified_date_time.unwrap_or_else(|| "-".into()),
            }
        })
        .collect())
}

async fn fetch_all_policies(client: &crate::graph::GraphClient) -> Result<Vec<PolicyData>> {
    let mut all = Vec::new();

    // Fetch each type, ignoring errors for individual types
    if let Ok(ca) = fetch_ca_policies(client).await {
        all.extend(ca);
    }
    if let Ok(compliance) = fetch_compliance_policies(client).await {
        all.extend(compliance);
    }
    if let Ok(config) = fetch_config_policies(client).await {
        all.extend(config);
    }

    Ok(all)
}

async fn deploy_baseline_async(
    config: &ConfigManager,
    tenant_name: &str,
    baseline_type: &str,
    baseline_data: &serde_json::Value,
    response_tx: &Sender<TaskResponse>,
    task_id: &str,
) -> TaskResult {
    use crate::graph::GraphClient;

    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 10,
        message: "Authenticating...".into(),
        phase: "auth".into(),
    }));

    let client = match GraphClient::from_config(config, tenant_name).await {
        Ok(c) => c,
        Err(e) => {
            return TaskResult::Error {
                message: format!("Authentication failed: {}", e),
            };
        }
    };

    let policies = baseline_data
        .get("policies")
        .and_then(|p| p.as_array())
        .map(|a| a.to_vec())
        .unwrap_or_default();

    let total = policies.len();
    let mut deployed = 0;
    let mut errors = Vec::new();

    for (i, policy) in policies.iter().enumerate() {
        let percent = ((i + 1) * 100 / total.max(1)) as u16;
        let policy_name = policy
            .get("displayName")
            .or_else(|| policy.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown");

        let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
            task_id: task_id.to_string(),
            percent,
            message: format!("Deploying: {}", policy_name),
            phase: "deploy".into(),
        }));

        // Determine endpoint based on policy type
        let odata_type = policy
            .get("@odata.type")
            .and_then(|t| t.as_str())
            .unwrap_or("");

        let endpoint = if odata_type.contains("deviceCompliancePolicy") {
            "deviceManagement/deviceCompliancePolicies"
        } else if odata_type.contains("configurationPolicy") {
            "deviceManagement/configurationPolicies"
        } else {
            continue; // Skip unknown types
        };

        match client
            .post_beta::<_, serde_json::Value>(endpoint, policy)
            .await
        {
            Ok(_) => deployed += 1,
            Err(e) => errors.push(format!("{}: {}", policy_name, e)),
        }
    }

    // Record audit
    crate::tui::change_tracker::record_baseline_deployed(baseline_type, deployed, tenant_name);

    if errors.is_empty() {
        TaskResult::BaselineDeployed {
            count: deployed,
            message: format!("Successfully deployed {} policies", deployed),
        }
    } else {
        TaskResult::BaselineDeployed {
            count: deployed,
            message: format!(
                "Deployed {} policies with {} errors: {}",
                deployed,
                errors.len(),
                errors.join("; ")
            ),
        }
    }
}

async fn deploy_ca_async(
    config: &ConfigManager,
    tenant_name: &str,
    response_tx: &Sender<TaskResponse>,
    task_id: &str,
) -> TaskResult {
    use crate::graph::GraphClient;
    use crate::templates::ca_baseline_2025;

    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 5,
        message: "Generating 44 CA policies...".into(),
        phase: "generate".into(),
    }));

    // Generate CA policies
    let baseline = ca_baseline_2025::CABaseline2025::generate();
    let policies: Vec<serde_json::Value> = baseline
        .policies
        .iter()
        .map(ca_baseline_2025::CABaseline2025::to_graph_json)
        .collect();

    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 10,
        message: "Authenticating...".into(),
        phase: "auth".into(),
    }));

    let client = match GraphClient::from_config(config, tenant_name).await {
        Ok(c) => c,
        Err(e) => {
            return TaskResult::Error {
                message: format!("Authentication failed: {}", e),
            };
        }
    };

    let total = policies.len();
    let mut deployed = 0;
    let mut errors = Vec::new();

    for (i, policy) in policies.iter().enumerate() {
        let percent = 10 + ((i + 1) * 90 / total.max(1)) as u16;
        let policy_name = policy
            .get("displayName")
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown");

        let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
            task_id: task_id.to_string(),
            percent,
            message: format!("Deploying: {}", policy_name),
            phase: "deploy".into(),
        }));

        match client
            .post::<_, serde_json::Value>("identity/conditionalAccess/policies", policy)
            .await
        {
            Ok(_) => deployed += 1,
            Err(e) => errors.push(format!("{}: {}", policy_name, e)),
        }

        // Small delay to avoid rate limiting
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Record audit
    crate::tui::change_tracker::record_baseline_deployed("CA Baseline 2025", deployed, tenant_name);

    if errors.is_empty() {
        TaskResult::CaDeployed {
            count: deployed,
            message: format!(
                "Successfully deployed {} CA policies in Report-Only mode",
                deployed
            ),
        }
    } else {
        TaskResult::CaDeployed {
            count: deployed,
            message: format!(
                "Deployed {} policies with {} errors",
                deployed,
                errors.len()
            ),
        }
    }
}

async fn apply_settings_async(
    config: &ConfigManager,
    tenant_name: &str,
    category: &SettingsCategory,
    settings: &std::collections::HashMap<String, bool>,
    response_tx: &Sender<TaskResponse>,
    task_id: &str,
) -> TaskResult {
    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 20,
        message: "Authenticating...".into(),
        phase: "auth".into(),
    }));

    // Build TenantConfiguration from settings
    use crate::tui::settings::TenantConfiguration;
    let mut tenant_config = TenantConfiguration::recommended();

    for (key, &value) in settings {
        match key.as_str() {
            "safe_links" => tenant_config.safe_links_enabled = value,
            "safe_links_teams" => tenant_config.safe_links_teams = value,
            "safe_links_office" => tenant_config.safe_links_office = value,
            "safe_attachments" => tenant_config.safe_attachments_enabled = value,
            "archive" => tenant_config.archive_mailbox = value,
            "forwarding" => tenant_config.external_forwarding_blocked = value,
            "zap" => tenant_config.zap_enabled = value,
            "external_access" => tenant_config.external_access = value,
            "guest_access" => tenant_config.teams_consumer_access = value,
            "meeting_recording" => tenant_config.meeting_recording = value,
            "anonymous_join" => tenant_config.anonymous_meeting_join = value,
            _ => {}
        }
    }

    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 50,
        message: "Applying settings...".into(),
        phase: "apply".into(),
    }));

    let category_name = match category {
        SettingsCategory::Defender => "Defender",
        SettingsCategory::Exchange => "Exchange",
        SettingsCategory::SharePoint => "SharePoint",
        SettingsCategory::Teams => "Teams",
        SettingsCategory::All => "All",
    };

    // Apply based on category
    let result = match category {
        SettingsCategory::Defender => {
            crate::tui::menu::apply_defender_settings_from_config(
                config,
                tenant_name,
                &tenant_config,
            )
            .await
        }
        SettingsCategory::Exchange => {
            crate::tui::menu::apply_exchange_settings_from_config(
                config,
                tenant_name,
                &tenant_config,
            )
            .await
        }
        SettingsCategory::SharePoint => {
            crate::tui::menu::apply_sharepoint_settings_from_config(
                config,
                tenant_name,
                &tenant_config,
            )
            .await
        }
        SettingsCategory::Teams => {
            crate::tui::menu::apply_teams_settings_from_config(config, tenant_name, &tenant_config)
                .await
        }
        SettingsCategory::All => {
            crate::tui::menu::apply_all_settings_from_config(config, tenant_name, &tenant_config)
                .await
        }
    };

    let _ = response_tx.send(TaskResponse::Progress(TaskProgress {
        task_id: task_id.to_string(),
        percent: 100,
        message: "Complete".into(),
        phase: "done".into(),
    }));

    match result {
        Ok(msg) => {
            crate::tui::change_tracker::record_setting_change(
                category_name,
                "Settings Applied",
                None,
                "Configured via TUI",
                tenant_name,
            );
            TaskResult::SettingsApplied { message: msg }
        }
        Err(e) => {
            crate::tui::change_tracker::record_error(
                "Settings",
                category_name,
                &e.to_string(),
                tenant_name,
            );
            TaskResult::Error {
                message: e.to_string(),
            }
        }
    }
}

async fn test_auth_async(config: &ConfigManager, tenant_name: &str) -> TaskResult {
    use crate::graph::GraphClient;

    match GraphClient::from_config(config, tenant_name).await {
        Ok(client) => {
            // Try a simple API call to verify token works
            #[derive(serde::Deserialize)]
            struct OrgInfo {
                #[serde(default)]
                value: Vec<serde_json::Value>,
            }

            match client.get::<OrgInfo>("organization").await {
                Ok(_) => {
                    crate::tui::change_tracker::record_auth(tenant_name, true, None);
                    TaskResult::AuthResult {
                        success: true,
                        message: format!("Successfully authenticated to {}", tenant_name),
                    }
                }
                Err(e) => {
                    crate::tui::change_tracker::record_auth(
                        tenant_name,
                        false,
                        Some(&e.to_string()),
                    );
                    TaskResult::AuthResult {
                        success: false,
                        message: format!("API call failed: {}", e),
                    }
                }
            }
        }
        Err(e) => {
            crate::tui::change_tracker::record_auth(tenant_name, false, Some(&e.to_string()));
            TaskResult::AuthResult {
                success: false,
                message: format!("Authentication failed: {}", e),
            }
        }
    }
}
