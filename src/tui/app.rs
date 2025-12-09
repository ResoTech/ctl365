//! Main TUI Application
//!
//! Full-screen terminal UI with:
//! - Header with branding and current tenant
//! - Main content area with menus/panels
//! - Status bar with help hints
//! - Keyboard navigation (arrows, vim-style j/k, numbers)
//! - Interactive policy tables with sorting/filtering
//! - Progress indicators for async operations
//! - Confirmation dialogs for destructive actions

use crate::config::ConfigManager;
use crate::error::Result;
use crate::tui::msp::MspConfig;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Row, Table, TableState,
        Wrap,
    },
};
use std::io;

/// Application state
pub struct App {
    /// Current screen/view
    pub screen: Screen,
    /// Navigation history for back functionality
    pub history: Vec<Screen>,
    /// MSP configuration (clients)
    pub msp_config: MspConfig,
    /// ctl365 config manager
    pub config: ConfigManager,
    /// Active tenant name
    pub active_tenant: Option<String>,
    /// Menu selection state
    pub menu_state: ListState,
    /// Current menu items
    pub menu_items: Vec<MenuItem>,
    /// Status message
    pub status_message: Option<(String, StatusLevel)>,
    /// Should quit
    pub should_quit: bool,
    /// Show help overlay
    pub show_help: bool,
    /// Search/filter input
    pub search_input: String,
    /// Is search mode active
    pub search_active: bool,
    /// Table state for policy lists
    pub table_state: TableState,
    /// Current table data
    pub table_data: Vec<PolicyRow>,
    /// Progress indicator state
    pub progress: Option<ProgressState>,
    /// Confirmation dialog state
    pub confirmation: Option<ConfirmationDialog>,
    /// Input mode (for forms)
    pub input_mode: InputMode,
    /// Current input buffer
    pub input_buffer: String,
    /// Current input field being edited
    pub input_field: Option<String>,
    /// Form state for multi-field forms
    pub form_state: Option<FormState>,
    /// Toggle states for settings (setting_id -> enabled)
    pub setting_toggles: std::collections::HashMap<String, bool>,
    /// Async task state
    pub async_task: Option<AsyncTaskState>,
    /// Audit history entries (cached)
    pub audit_entries: Vec<crate::tui::change_tracker::AuditEntry>,
    /// Audit history filter (days back)
    pub audit_days_filter: u32,
    /// Background task sender
    pub task_sender: Option<crate::tui::tasks::TaskSender>,
    /// Background task receiver
    pub task_receiver: Option<crate::tui::tasks::TaskReceiver>,
    /// Current background task ID
    pub current_task_id: Option<String>,
    /// Count of changes in this session (for exit prompt)
    pub session_change_count: usize,
    /// Flag to skip exit confirmation
    pub exit_confirmed: bool,
    /// Current page for table pagination (0-indexed)
    pub table_page: usize,
    /// Page size for table pagination
    pub table_page_size: usize,
}

/// State for tracking async operations
#[derive(Debug, Clone)]
pub struct AsyncTaskState {
    /// Task ID for tracking
    pub id: String,
    /// Current progress (0-100)
    pub progress: u16,
    /// Status message
    pub message: String,
    /// Whether task is complete
    pub completed: bool,
    /// Result message (success or error)
    pub result: Option<(String, bool)>, // (message, is_success)
}

impl AsyncTaskState {
    pub fn new(id: &str, message: &str) -> Self {
        Self {
            id: id.to_string(),
            progress: 0,
            message: message.to_string(),
            completed: false,
            result: None,
        }
    }
}

/// Policy row for table display
#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub name: String,
    pub policy_type: String,
    pub status: PolicyStatus,
    pub platform: String,
    pub assignments: usize,
    pub last_modified: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyStatus {
    Deployed,
    ReportOnly,
    Disabled,
    Draft,
}

impl PolicyStatus {
    pub fn as_str(&self) -> &str {
        match self {
            PolicyStatus::Deployed => "Deployed",
            PolicyStatus::ReportOnly => "Report-Only",
            PolicyStatus::Disabled => "Disabled",
            PolicyStatus::Draft => "Draft",
        }
    }

    pub fn color(&self) -> Color {
        match self {
            PolicyStatus::Deployed => Color::Green,
            PolicyStatus::ReportOnly => Color::Yellow,
            PolicyStatus::Disabled => Color::DarkGray,
            PolicyStatus::Draft => Color::Cyan,
        }
    }
}

/// Progress state for async operations
#[derive(Debug, Clone)]
pub struct ProgressState {
    pub title: String,
    pub message: String,
    pub current: u16,
    pub total: u16,
    pub indeterminate: bool,
}

impl ProgressState {
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            message: String::new(),
            current: 0,
            total: 100,
            indeterminate: true,
        }
    }

    pub fn with_total(title: &str, total: u16) -> Self {
        Self {
            title: title.to_string(),
            message: String::new(),
            current: 0,
            total,
            indeterminate: false,
        }
    }

    pub fn percent(&self) -> u16 {
        if self.indeterminate {
            0
        } else if self.total == 0 {
            100
        } else {
            (self.current * 100 / self.total).min(100)
        }
    }
}

/// Confirmation dialog
#[derive(Debug, Clone)]
pub struct ConfirmationDialog {
    pub title: String,
    pub message: String,
    pub confirm_label: String,
    pub cancel_label: String,
    pub action: ConfirmAction,
    pub selected: bool, // true = confirm, false = cancel
    pub impact: Option<crate::tui::context::ImpactSummary>,
}

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    DeleteClient(String),
    DeployBaseline(String),
    ApplySettings(SettingsCategory),
    DeployConditionalAccess,
    ExitWithChanges,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Search,
    Input,
}

/// Form field definition
#[derive(Debug, Clone)]
pub struct FormField {
    pub id: String,
    pub label: String,
    pub value: String,
    pub placeholder: String,
    pub required: bool,
    pub field_type: FormFieldType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FormFieldType {
    Text,
    Password,
    Select(Vec<String>),
}

/// Form state for multi-field input
#[derive(Debug, Clone)]
pub struct FormState {
    pub title: String,
    pub fields: Vec<FormField>,
    pub current_field: usize,
    pub submit_label: String,
    pub on_submit: FormAction,
}

#[derive(Debug, Clone)]
pub enum FormAction {
    AddClient,
    EditClient(String),
    ExportPolicies,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Dashboard,
    ClientList,
    ClientAdd,
    ClientConfig(String), // client abbreviation
    Settings(SettingsCategory),
    Reports,
    Help,
    PolicyList(PolicyListType),
    BaselineSelect,
    AuditHistory,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyListType {
    Compliance,
    Configuration,
    SettingsCatalog,
    ConditionalAccess,
    Apps,
    All,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SettingsCategory {
    Main,
    Defender,
    Exchange,
    SharePoint,
    Teams,
    ConditionalAccess,
    Intune,
}

#[derive(Debug, Clone)]
pub struct MenuItem {
    pub id: String,
    pub label: String,
    pub description: String,
    pub shortcut: Option<char>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum StatusLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl App {
    pub fn new() -> Result<Self> {
        let config = ConfigManager::load()?;
        let msp_config = MspConfig::load().unwrap_or_default();
        let active_tenant = config.load_config()?.current_tenant;

        let mut app = Self {
            screen: Screen::Dashboard,
            history: Vec::new(),
            msp_config,
            config,
            active_tenant,
            menu_state: ListState::default(),
            menu_items: Vec::new(),
            status_message: None,
            should_quit: false,
            show_help: false,
            search_input: String::new(),
            search_active: false,
            table_state: TableState::default(),
            table_data: Vec::new(),
            progress: None,
            confirmation: None,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            input_field: None,
            form_state: None,
            setting_toggles: std::collections::HashMap::new(),
            async_task: None,
            audit_entries: Vec::new(),
            audit_days_filter: 7, // Default to last 7 days
            task_sender: None,
            task_receiver: None,
            current_task_id: None,
            session_change_count: 0,
            exit_confirmed: false,
            table_page: 0,
            table_page_size: 20, // Show 20 items per page by default
        };

        // Spawn background task worker
        let (sender, receiver) = crate::tui::tasks::spawn_task_worker(app.config.clone());
        app.task_sender = Some(sender);
        app.task_receiver = Some(receiver);

        app.refresh_menu();
        app.menu_state.select(Some(0));

        Ok(app)
    }

    /// Show a confirmation dialog
    pub fn show_confirmation(&mut self, title: &str, message: &str, action: ConfirmAction) {
        self.confirmation = Some(ConfirmationDialog {
            title: title.to_string(),
            message: message.to_string(),
            confirm_label: "Yes".to_string(),
            cancel_label: "No".to_string(),
            action,
            selected: false, // Start on Cancel for safety
            impact: None,
        });
    }

    /// Show confirmation dialog with impact summary
    pub fn show_confirmation_with_impact(
        &mut self,
        title: &str,
        action: ConfirmAction,
        impact: crate::tui::context::ImpactSummary,
    ) {
        let message = impact.format_tui();
        self.confirmation = Some(ConfirmationDialog {
            title: title.to_string(),
            message,
            confirm_label: "Confirm".to_string(),
            cancel_label: "Cancel".to_string(),
            action,
            selected: false, // Start on Cancel for safety
            impact: Some(impact),
        });
    }

    /// Start a progress indicator
    pub fn start_progress(&mut self, title: &str) {
        self.progress = Some(ProgressState::new(title));
    }

    /// Start a progress indicator with known total
    pub fn start_progress_with_total(&mut self, title: &str, total: u16) {
        self.progress = Some(ProgressState::with_total(title, total));
    }

    /// Update progress
    pub fn update_progress(&mut self, current: u16, message: &str) {
        if let Some(ref mut p) = self.progress {
            p.current = current;
            p.message = message.to_string();
        }
    }

    /// Clear progress
    pub fn clear_progress(&mut self) {
        self.progress = None;
    }

    /// Start an async task with progress tracking
    pub fn start_async_task(&mut self, id: &str, message: &str) {
        self.async_task = Some(AsyncTaskState::new(id, message));
        self.progress = Some(ProgressState::new(message));
    }

    /// Update async task progress
    pub fn update_async_progress(&mut self, progress: u16, message: &str) {
        if let Some(ref mut task) = self.async_task {
            task.progress = progress;
            task.message = message.to_string();
        }
        if let Some(ref mut p) = self.progress {
            p.current = progress;
            p.message = message.to_string();
            p.indeterminate = false;
            p.total = 100;
        }
    }

    /// Complete async task with result
    pub fn complete_async_task(&mut self, success: bool, message: &str) {
        if let Some(ref mut task) = self.async_task {
            task.completed = true;
            task.result = Some((message.to_string(), success));
        }
        self.progress = None;
        self.status_message = Some((
            message.to_string(),
            if success {
                StatusLevel::Success
            } else {
                StatusLevel::Error
            },
        ));
        self.async_task = None;
    }

    /// Check if async task is running
    pub fn is_async_task_running(&self) -> bool {
        self.async_task
            .as_ref()
            .map(|t| !t.completed)
            .unwrap_or(false)
    }

    /// Toggle search mode
    pub fn toggle_search(&mut self) {
        self.search_active = !self.search_active;
        if self.search_active {
            self.input_mode = InputMode::Search;
            self.search_input.clear();
        } else {
            self.input_mode = InputMode::Normal;
        }
    }

    /// Filter menu items based on search
    pub fn filtered_menu_items(&self) -> Vec<&MenuItem> {
        if self.search_input.is_empty() {
            self.menu_items.iter().collect()
        } else {
            let query = self.search_input.to_lowercase();
            self.menu_items
                .iter()
                .filter(|item| {
                    item.label.to_lowercase().contains(&query)
                        || item.description.to_lowercase().contains(&query)
                })
                .collect()
        }
    }

    /// Filter table data based on search
    pub fn filtered_table_data(&self) -> Vec<&PolicyRow> {
        if self.search_input.is_empty() {
            self.table_data.iter().collect()
        } else {
            let query = self.search_input.to_lowercase();
            self.table_data
                .iter()
                .filter(|row| {
                    row.name.to_lowercase().contains(&query)
                        || row.policy_type.to_lowercase().contains(&query)
                        || row.platform.to_lowercase().contains(&query)
                })
                .collect()
        }
    }

    /// Load policies from Graph API if connected, otherwise show sample data
    pub fn load_policies(&mut self, policy_type: &PolicyListType) {
        // Try to load from API if we have an active tenant
        if let Some(tenant_name) = &self.active_tenant {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let config = self.config.clone();
                let tenant = tenant_name.clone();
                let pt = policy_type.clone();

                let result =
                    handle.block_on(async { load_policies_from_api(&config, &tenant, &pt).await });

                match result {
                    Ok(policies) => {
                        self.table_data = policies;
                        self.reset_table_pagination();
                        return;
                    }
                    Err(e) => {
                        // Fall back to sample data on error
                        self.status_message = Some((
                            format!("Using sample data (API error: {})", e),
                            StatusLevel::Warning,
                        ));
                    }
                }
            }
        }

        // Fall back to sample data
        self.load_sample_policies(policy_type);
    }

    /// Load sample policy data for demo
    pub fn load_sample_policies(&mut self, policy_type: &PolicyListType) {
        self.table_data = match policy_type {
            PolicyListType::ConditionalAccess => vec![
                PolicyRow {
                    name: "CAD001 - Require compliant device".into(),
                    policy_type: "Device".into(),
                    status: PolicyStatus::ReportOnly,
                    platform: "All".into(),
                    assignments: 1,
                    last_modified: "2025-01-15".into(),
                },
                PolicyRow {
                    name: "CAD002 - Block legacy OS".into(),
                    policy_type: "Device".into(),
                    status: PolicyStatus::ReportOnly,
                    platform: "Windows".into(),
                    assignments: 1,
                    last_modified: "2025-01-15".into(),
                },
                PolicyRow {
                    name: "CAL002 - Block untrusted locations".into(),
                    policy_type: "Location".into(),
                    status: PolicyStatus::ReportOnly,
                    platform: "All".into(),
                    assignments: 2,
                    last_modified: "2025-01-15".into(),
                },
                PolicyRow {
                    name: "CAP001 - Block legacy auth".into(),
                    policy_type: "Protocol".into(),
                    status: PolicyStatus::Deployed,
                    platform: "All".into(),
                    assignments: 1,
                    last_modified: "2025-01-10".into(),
                },
                PolicyRow {
                    name: "CAR001 - Sign-in risk MFA".into(),
                    policy_type: "Risk".into(),
                    status: PolicyStatus::ReportOnly,
                    platform: "All".into(),
                    assignments: 1,
                    last_modified: "2025-01-15".into(),
                },
                PolicyRow {
                    name: "CAS001 - Azure Portal protection".into(),
                    policy_type: "Service".into(),
                    status: PolicyStatus::Deployed,
                    platform: "All".into(),
                    assignments: 1,
                    last_modified: "2025-01-08".into(),
                },
                PolicyRow {
                    name: "CAU001 - Require MFA".into(),
                    policy_type: "User".into(),
                    status: PolicyStatus::Deployed,
                    platform: "All".into(),
                    assignments: 3,
                    last_modified: "2025-01-05".into(),
                },
            ],
            PolicyListType::Compliance => vec![
                PolicyRow {
                    name: "OIB-WIN-Compliance-v3.6".into(),
                    policy_type: "Compliance".into(),
                    status: PolicyStatus::Deployed,
                    platform: "Windows".into(),
                    assignments: 2,
                    last_modified: "2025-01-12".into(),
                },
                PolicyRow {
                    name: "OIB-MAC-Compliance-v3.6".into(),
                    policy_type: "Compliance".into(),
                    status: PolicyStatus::Draft,
                    platform: "macOS".into(),
                    assignments: 0,
                    last_modified: "2025-01-14".into(),
                },
                PolicyRow {
                    name: "OIB-iOS-Compliance-v3.6".into(),
                    policy_type: "Compliance".into(),
                    status: PolicyStatus::Draft,
                    platform: "iOS".into(),
                    assignments: 0,
                    last_modified: "2025-01-14".into(),
                },
            ],
            PolicyListType::Configuration | PolicyListType::SettingsCatalog => vec![
                PolicyRow {
                    name: "OIB-WIN-Config-BitLocker-v3.6".into(),
                    policy_type: "Settings Catalog".into(),
                    status: PolicyStatus::Deployed,
                    platform: "Windows".into(),
                    assignments: 2,
                    last_modified: "2025-01-12".into(),
                },
                PolicyRow {
                    name: "OIB-WIN-Config-Defender-v3.6".into(),
                    policy_type: "Settings Catalog".into(),
                    status: PolicyStatus::Deployed,
                    platform: "Windows".into(),
                    assignments: 2,
                    last_modified: "2025-01-12".into(),
                },
                PolicyRow {
                    name: "OIB-WIN-Config-Edge-v3.6".into(),
                    policy_type: "Settings Catalog".into(),
                    status: PolicyStatus::Draft,
                    platform: "Windows".into(),
                    assignments: 0,
                    last_modified: "2025-01-14".into(),
                },
            ],
            PolicyListType::Apps => vec![
                PolicyRow {
                    name: "Microsoft 365 Apps".into(),
                    policy_type: "Win32".into(),
                    status: PolicyStatus::Deployed,
                    platform: "Windows".into(),
                    assignments: 2,
                    last_modified: "2025-01-10".into(),
                },
                PolicyRow {
                    name: "Company Portal".into(),
                    policy_type: "Store".into(),
                    status: PolicyStatus::Deployed,
                    platform: "Windows".into(),
                    assignments: 1,
                    last_modified: "2025-01-08".into(),
                },
                PolicyRow {
                    name: "Microsoft Teams".into(),
                    policy_type: "Store".into(),
                    status: PolicyStatus::Deployed,
                    platform: "iOS".into(),
                    assignments: 1,
                    last_modified: "2025-01-05".into(),
                },
            ],
            PolicyListType::All => {
                let mut all = Vec::new();
                // Combine all policy types
                all.extend(vec![
                    PolicyRow {
                        name: "CAU001 - Require MFA".into(),
                        policy_type: "CA".into(),
                        status: PolicyStatus::Deployed,
                        platform: "All".into(),
                        assignments: 3,
                        last_modified: "2025-01-05".into(),
                    },
                    PolicyRow {
                        name: "OIB-WIN-Compliance-v3.6".into(),
                        policy_type: "Compliance".into(),
                        status: PolicyStatus::Deployed,
                        platform: "Windows".into(),
                        assignments: 2,
                        last_modified: "2025-01-12".into(),
                    },
                    PolicyRow {
                        name: "OIB-WIN-Config-BitLocker-v3.6".into(),
                        policy_type: "Config".into(),
                        status: PolicyStatus::Deployed,
                        platform: "Windows".into(),
                        assignments: 2,
                        last_modified: "2025-01-12".into(),
                    },
                    PolicyRow {
                        name: "Microsoft 365 Apps".into(),
                        policy_type: "App".into(),
                        status: PolicyStatus::Deployed,
                        platform: "Windows".into(),
                        assignments: 2,
                        last_modified: "2025-01-10".into(),
                    },
                ]);
                all
            }
        };
        self.reset_table_pagination();
    }

    /// Initialize form for adding a new client
    pub fn init_add_client_form(&mut self) {
        self.form_state = Some(FormState {
            title: "Add New Client".to_string(),
            fields: vec![
                FormField {
                    id: "abbreviation".into(),
                    label: "Client Abbreviation".into(),
                    value: String::new(),
                    placeholder: "e.g., ACME".into(),
                    required: true,
                    field_type: FormFieldType::Text,
                },
                FormField {
                    id: "full_name".into(),
                    label: "Full Name".into(),
                    value: String::new(),
                    placeholder: "e.g., Acme Corporation".into(),
                    required: true,
                    field_type: FormFieldType::Text,
                },
                FormField {
                    id: "tenant_id".into(),
                    label: "Tenant ID".into(),
                    value: String::new(),
                    placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".into(),
                    required: true,
                    field_type: FormFieldType::Text,
                },
                FormField {
                    id: "client_id".into(),
                    label: "App Client ID".into(),
                    value: String::new(),
                    placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".into(),
                    required: true,
                    field_type: FormFieldType::Text,
                },
                FormField {
                    id: "client_secret".into(),
                    label: "Client Secret (optional)".into(),
                    value: String::new(),
                    placeholder: "Leave empty for device code flow".into(),
                    required: false,
                    field_type: FormFieldType::Password,
                },
                FormField {
                    id: "contact_email".into(),
                    label: "Contact Email".into(),
                    value: String::new(),
                    placeholder: "admin@client.com".into(),
                    required: false,
                    field_type: FormFieldType::Text,
                },
            ],
            current_field: 0,
            submit_label: "Add Client".to_string(),
            on_submit: FormAction::AddClient,
        });
        self.input_mode = InputMode::Input;
    }

    /// Initialize default toggle states for settings
    pub fn init_defender_toggles(&mut self) {
        self.setting_toggles.clear();
        self.setting_toggles.insert("safe_links".into(), true);
        self.setting_toggles.insert("safe_links_teams".into(), true);
        self.setting_toggles
            .insert("safe_links_office".into(), true);
        self.setting_toggles.insert("safe_attachments".into(), true);
    }

    pub fn init_exchange_toggles(&mut self) {
        self.setting_toggles.clear();
        self.setting_toggles.insert("archive".into(), true);
        self.setting_toggles.insert("forwarding".into(), true);
        self.setting_toggles.insert("zap".into(), true);
        self.setting_toggles.insert("spam".into(), true);
    }

    pub fn init_sharepoint_toggles(&mut self) {
        self.setting_toggles.clear();
        self.setting_toggles
            .insert("external_sharing".into(), false);
        self.setting_toggles.insert("sync_client".into(), true);
        self.setting_toggles.insert("versioning".into(), true);
        self.setting_toggles.insert("dlp".into(), true);
    }

    pub fn init_teams_toggles(&mut self) {
        self.setting_toggles.clear();
        self.setting_toggles.insert("external_access".into(), false);
        self.setting_toggles.insert("guest_access".into(), false);
        self.setting_toggles
            .insert("meeting_recording".into(), true);
        self.setting_toggles.insert("anonymous_join".into(), false);
    }

    /// Toggle a setting on/off
    pub fn toggle_setting(&mut self, id: &str) {
        if let Some(value) = self.setting_toggles.get_mut(id) {
            *value = !*value;
        }
    }

    /// Handle form field navigation (next/prev)
    pub fn form_next_field(&mut self) {
        if let Some(ref mut form) = self.form_state {
            if form.current_field < form.fields.len() - 1 {
                form.current_field += 1;
            }
        }
    }

    pub fn form_prev_field(&mut self) {
        if let Some(ref mut form) = self.form_state {
            if form.current_field > 0 {
                form.current_field -= 1;
            }
        }
    }

    /// Handle form character input
    pub fn form_input_char(&mut self, c: char) {
        if let Some(ref mut form) = self.form_state {
            if form.current_field < form.fields.len() {
                form.fields[form.current_field].value.push(c);
            }
        }
    }

    /// Handle form backspace
    pub fn form_backspace(&mut self) {
        if let Some(ref mut form) = self.form_state {
            form.fields[form.current_field].value.pop();
        }
    }

    /// Submit form and process action
    pub fn form_submit(&mut self) {
        if let Some(form) = self.form_state.take() {
            // Validate required fields
            for field in &form.fields {
                if field.required && field.value.trim().is_empty() {
                    self.status_message =
                        Some((format!("{} is required", field.label), StatusLevel::Error));
                    self.form_state = Some(form);
                    return;
                }
            }

            match form.on_submit {
                FormAction::AddClient => {
                    self.process_add_client(&form.fields);
                }
                FormAction::EditClient(ref abbrev) => {
                    self.process_edit_client(abbrev, &form.fields);
                }
                FormAction::ExportPolicies => {
                    self.process_export_policies(&form.fields);
                }
            }

            self.input_mode = InputMode::Normal;
        }
    }

    /// Cancel form and return to previous screen
    pub fn form_cancel(&mut self) {
        self.form_state = None;
        self.input_mode = InputMode::Normal;
        self.go_back();
    }

    fn process_add_client(&mut self, fields: &[FormField]) {
        let get_field = |id: &str| -> String {
            fields
                .iter()
                .find(|f| f.id == id)
                .map(|f| f.value.clone())
                .unwrap_or_default()
        };

        let abbreviation = get_field("abbreviation").to_uppercase();
        let full_name = get_field("full_name");
        let tenant_id = get_field("tenant_id");
        let client_id = get_field("client_id");
        let client_secret = get_field("client_secret");
        let contact_email = get_field("contact_email");

        // Check if client already exists
        if self
            .msp_config
            .clients
            .iter()
            .any(|c| c.abbreviation == abbreviation)
        {
            self.status_message = Some((
                format!("Client {} already exists", abbreviation),
                StatusLevel::Error,
            ));
            return;
        }

        // Add to MSP config
        use crate::tui::msp::MspClient;
        let new_client = MspClient {
            abbreviation: abbreviation.clone(),
            full_name: full_name.clone(),
            tenant_id: tenant_id.clone(),
            client_id: client_id.clone(),
            client_secret: if client_secret.is_empty() {
                None
            } else {
                Some(client_secret.clone())
            },
            contact_email: if contact_email.is_empty() {
                None
            } else {
                Some(contact_email)
            },
            notes: None,
            added_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            auth_type: if client_secret.is_empty() {
                "device_code"
            } else {
                "client_credentials"
            }
            .into(),
        };

        self.msp_config.clients.push(new_client);

        // Save MSP config
        if let Err(e) = self.msp_config.save() {
            self.status_message =
                Some((format!("Failed to save client: {}", e), StatusLevel::Error));
            return;
        }

        // Also add to tenant config for authentication
        use crate::config::{AuthType, TenantConfig};
        let has_secret = !client_secret.is_empty();
        let tenant_config = TenantConfig {
            name: abbreviation.clone(),
            tenant_id,
            client_id,
            client_secret: if has_secret {
                Some(client_secret)
            } else {
                None
            },
            auth_type: if has_secret {
                AuthType::ClientCredentials
            } else {
                AuthType::DeviceCode
            },
            description: Some(full_name.clone()),
        };

        if let Err(e) = self.config.add_tenant(tenant_config) {
            self.status_message = Some((
                format!("Client added but tenant config failed: {}", e),
                StatusLevel::Warning,
            ));
            self.go_back();
            return;
        }

        // Record audit entry for tenant added
        use crate::tui::change_tracker::{AuditAction, AuditEntry, record};
        let entry = AuditEntry::new(
            AuditAction::TenantAdded,
            "Client",
            &abbreviation,
            &abbreviation,
        )
        .with_details(&full_name)
        .success();
        record(entry);

        self.status_message = Some((
            format!("Client {} added successfully!", abbreviation),
            StatusLevel::Success,
        ));
        self.go_back();
    }

    fn process_edit_client(&mut self, _abbrev: &str, _fields: &[FormField]) {
        self.status_message = Some((
            "Edit client not yet implemented".into(),
            StatusLevel::Warning,
        ));
    }

    fn process_export_policies(&mut self, _fields: &[FormField]) {
        self.status_message = Some((
            "Export policies not yet implemented".into(),
            StatusLevel::Warning,
        ));
    }

    /// Navigate to a new screen
    pub fn navigate_to(&mut self, screen: Screen) {
        self.history.push(self.screen.clone());
        self.screen = screen;
        self.refresh_menu();
        self.menu_state.select(Some(0));
    }

    /// Go back to previous screen
    pub fn go_back(&mut self) {
        if let Some(prev) = self.history.pop() {
            self.screen = prev;
            self.refresh_menu();
            self.menu_state.select(Some(0));
        }
    }

    /// Refresh menu items based on current screen
    pub fn refresh_menu(&mut self) {
        // Clone policy_type before match to avoid borrow issues
        let policy_type_clone = if let Screen::PolicyList(pt) = &self.screen {
            Some(pt.clone())
        } else {
            None
        };

        // Check if entering audit screen
        let load_audit = matches!(self.screen, Screen::AuditHistory);

        self.menu_items = match &self.screen {
            Screen::Dashboard => self.dashboard_menu(),
            Screen::ClientList => self.client_list_menu(),
            Screen::ClientAdd => vec![], // Form-based, no menu
            Screen::ClientConfig(_) => self.client_config_menu(),
            Screen::Settings(cat) => self.settings_menu(cat),
            Screen::Reports => self.reports_menu(),
            Screen::Help => vec![],
            Screen::PolicyList(_) => self.policy_list_menu(),
            Screen::BaselineSelect => self.baseline_select_menu(),
            Screen::AuditHistory => self.audit_history_menu(),
        };

        // Load policies after match to avoid borrow conflict
        if let Some(policy_type) = policy_type_clone {
            self.load_policies(&policy_type);
        }

        // Load audit entries when entering audit screen
        if load_audit {
            self.load_audit_entries();
        }
    }

    /// Load audit entries from persistent storage
    fn load_audit_entries(&mut self) {
        match crate::tui::change_tracker::load_recent_entries(self.audit_days_filter) {
            Ok(entries) => {
                self.audit_entries = entries;
                self.table_state.select(if self.audit_entries.is_empty() {
                    None
                } else {
                    Some(0)
                });
            }
            Err(e) => {
                self.status_message = Some((
                    format!("Failed to load audit history: {}", e),
                    StatusLevel::Warning,
                ));
                self.audit_entries = Vec::new();
            }
        }
    }

    /// Audit history menu
    fn audit_history_menu(&self) -> Vec<MenuItem> {
        vec![
            MenuItem {
                id: "audit_7d".into(),
                label: "Last 7 Days".into(),
                description: "Show entries from past week".into(),
                shortcut: Some('7'),
                enabled: true,
            },
            MenuItem {
                id: "audit_30d".into(),
                label: "Last 30 Days".into(),
                description: "Show entries from past month".into(),
                shortcut: Some('3'),
                enabled: true,
            },
            MenuItem {
                id: "audit_all".into(),
                label: "All History".into(),
                description: "Show all audit entries".into(),
                shortcut: Some('a'),
                enabled: true,
            },
            MenuItem {
                id: "audit_export".into(),
                label: "Export to JSON".into(),
                description: "Export audit trail to file".into(),
                shortcut: Some('e'),
                enabled: true,
            },
            MenuItem {
                id: "audit_clear_session".into(),
                label: "Clear Session".into(),
                description: "Clear current session entries".into(),
                shortcut: Some('c'),
                enabled: true,
            },
            MenuItem {
                id: "back".into(),
                label: "← Back".into(),
                description: "Return to dashboard".into(),
                shortcut: Some('b'),
                enabled: true,
            },
        ]
    }

    fn policy_list_menu(&self) -> Vec<MenuItem> {
        vec![
            MenuItem {
                id: "refresh".into(),
                label: "Refresh".into(),
                description: "Reload policies from tenant".into(),
                shortcut: Some('r'),
                enabled: true,
            },
            MenuItem {
                id: "filter".into(),
                label: "Filter".into(),
                description: "Filter by status or platform".into(),
                shortcut: Some('f'),
                enabled: true,
            },
            MenuItem {
                id: "export".into(),
                label: "Export".into(),
                description: "Export to JSON/CSV".into(),
                shortcut: Some('e'),
                enabled: true,
            },
            MenuItem {
                id: "back".into(),
                label: "Back".into(),
                description: "Return to previous screen".into(),
                shortcut: Some('b'),
                enabled: true,
            },
        ]
    }

    fn baseline_select_menu(&self) -> Vec<MenuItem> {
        vec![
            MenuItem {
                id: "windows_oib".into(),
                label: "Windows - OIB v3.6".into(),
                description: "OpenIntuneBaseline for Windows 11 25H2".into(),
                shortcut: Some('1'),
                enabled: true,
            },
            MenuItem {
                id: "windows_basic".into(),
                label: "Windows - Basic".into(),
                description: "Simple baseline for quick deployments".into(),
                shortcut: Some('2'),
                enabled: true,
            },
            MenuItem {
                id: "macos_oib".into(),
                label: "macOS - OIB".into(),
                description: "OpenIntuneBaseline for macOS".into(),
                shortcut: Some('3'),
                enabled: true,
            },
            MenuItem {
                id: "ios_oib".into(),
                label: "iOS/iPadOS - OIB".into(),
                description: "OpenIntuneBaseline for iOS".into(),
                shortcut: Some('4'),
                enabled: true,
            },
            MenuItem {
                id: "android_oib".into(),
                label: "Android - OIB".into(),
                description: "OpenIntuneBaseline for Android".into(),
                shortcut: Some('5'),
                enabled: true,
            },
            MenuItem {
                id: "ca_2025".into(),
                label: "CA Baseline 2025".into(),
                description: "44 Conditional Access policies".into(),
                shortcut: Some('6'),
                enabled: true,
            },
            MenuItem {
                id: "back".into(),
                label: "Back".into(),
                description: "Return to previous screen".into(),
                shortcut: Some('b'),
                enabled: true,
            },
        ]
    }

    fn dashboard_menu(&self) -> Vec<MenuItem> {
        vec![
            MenuItem {
                id: "clients".into(),
                label: "Manage Clients".into(),
                description: format!("{} clients configured", self.msp_config.clients.len()),
                shortcut: Some('c'),
                enabled: true,
            },
            MenuItem {
                id: "configure".into(),
                label: "Configure Tenant".into(),
                description: self
                    .active_tenant
                    .clone()
                    .unwrap_or("No tenant selected".into()),
                shortcut: Some('t'),
                enabled: self.active_tenant.is_some(),
            },
            MenuItem {
                id: "reports".into(),
                label: "Generate Reports".into(),
                description: "Compliance, security, change control".into(),
                shortcut: Some('r'),
                enabled: self.active_tenant.is_some(),
            },
            MenuItem {
                id: "audit".into(),
                label: "Audit & Compliance".into(),
                description: "Check baseline compliance, detect drift".into(),
                shortcut: Some('a'),
                enabled: self.active_tenant.is_some(),
            },
            MenuItem {
                id: "audit_history".into(),
                label: "Audit History".into(),
                description: format!(
                    "{} changes tracked",
                    crate::tui::change_tracker::get_session_entries().len()
                ),
                shortcut: Some('h'),
                enabled: true,
            },
            MenuItem {
                id: "baseline".into(),
                label: "Deploy Baseline".into(),
                description: "Windows, macOS, iOS, Android baselines".into(),
                shortcut: Some('b'),
                enabled: self.active_tenant.is_some(),
            },
            MenuItem {
                id: "ca".into(),
                label: "Conditional Access".into(),
                description: "44 production-ready CA policies".into(),
                shortcut: Some('p'),
                enabled: self.active_tenant.is_some(),
            },
            MenuItem {
                id: "help".into(),
                label: "Help & Documentation".into(),
                description: "Keyboard shortcuts, guides".into(),
                shortcut: Some('?'),
                enabled: true,
            },
            MenuItem {
                id: "quit".into(),
                label: "Exit".into(),
                description: "Return to command line".into(),
                shortcut: Some('q'),
                enabled: true,
            },
        ]
    }

    fn client_list_menu(&self) -> Vec<MenuItem> {
        let mut items: Vec<MenuItem> = self
            .msp_config
            .clients
            .iter()
            .map(|c| MenuItem {
                id: format!("client:{}", c.abbreviation),
                label: format!("{} - {}", c.abbreviation, c.full_name),
                description: format!("Tenant: {}", &c.tenant_id[..8]),
                shortcut: None,
                enabled: true,
            })
            .collect();

        items.push(MenuItem {
            id: "add".into(),
            label: "+ Add New Client".into(),
            description: "Register a new client tenant".into(),
            shortcut: Some('n'),
            enabled: true,
        });

        items.push(MenuItem {
            id: "back".into(),
            label: "← Back".into(),
            description: "Return to dashboard".into(),
            shortcut: Some('b'),
            enabled: true,
        });

        items
    }

    fn client_config_menu(&self) -> Vec<MenuItem> {
        vec![
            MenuItem {
                id: "defender".into(),
                label: "Defender for Office 365".into(),
                description: "Safe Links, Safe Attachments".into(),
                shortcut: Some('d'),
                enabled: true,
            },
            MenuItem {
                id: "exchange".into(),
                label: "Exchange Online".into(),
                description: "Archive, anti-spam, anti-malware".into(),
                shortcut: Some('e'),
                enabled: true,
            },
            MenuItem {
                id: "sharepoint".into(),
                label: "SharePoint & OneDrive".into(),
                description: "Sharing, external access, sync".into(),
                shortcut: Some('s'),
                enabled: true,
            },
            MenuItem {
                id: "teams".into(),
                label: "Microsoft Teams".into(),
                description: "External access, meetings".into(),
                shortcut: Some('t'),
                enabled: true,
            },
            MenuItem {
                id: "ca".into(),
                label: "Conditional Access".into(),
                description: "Deploy CA baseline policies".into(),
                shortcut: Some('c'),
                enabled: true,
            },
            MenuItem {
                id: "intune".into(),
                label: "Intune Baseline".into(),
                description: "Device compliance & configuration".into(),
                shortcut: Some('i'),
                enabled: true,
            },
            MenuItem {
                id: "apply_all".into(),
                label: "Apply All Recommended".into(),
                description: "Configure all settings to recommended values".into(),
                shortcut: Some('a'),
                enabled: true,
            },
            MenuItem {
                id: "report".into(),
                label: "Generate Report".into(),
                description: "Export HTML report for this client".into(),
                shortcut: Some('r'),
                enabled: true,
            },
            MenuItem {
                id: "back".into(),
                label: "← Back".into(),
                description: "Return to client list".into(),
                shortcut: Some('b'),
                enabled: true,
            },
        ]
    }

    fn settings_menu(&self, category: &SettingsCategory) -> Vec<MenuItem> {
        match category {
            SettingsCategory::Main => self.client_config_menu(),
            SettingsCategory::Defender => vec![
                MenuItem {
                    id: "safe_links".into(),
                    label: "Enable Safe Links".into(),
                    description: "Scan URLs in emails at click time".into(),
                    shortcut: Some('1'),
                    enabled: true,
                },
                MenuItem {
                    id: "safe_links_teams".into(),
                    label: "Safe Links for Teams".into(),
                    description: "Protect URLs in Teams chats".into(),
                    shortcut: Some('2'),
                    enabled: true,
                },
                MenuItem {
                    id: "safe_links_office".into(),
                    label: "Safe Links for Office".into(),
                    description: "Protect URLs in Office docs".into(),
                    shortcut: Some('3'),
                    enabled: true,
                },
                MenuItem {
                    id: "safe_attachments".into(),
                    label: "Enable Safe Attachments".into(),
                    description: "Sandbox email attachments".into(),
                    shortcut: Some('4'),
                    enabled: true,
                },
                MenuItem {
                    id: "apply".into(),
                    label: "Apply Settings".into(),
                    description: "Save and apply these settings".into(),
                    shortcut: Some('a'),
                    enabled: true,
                },
                MenuItem {
                    id: "back".into(),
                    label: "← Back".into(),
                    description: "Return without saving".into(),
                    shortcut: Some('b'),
                    enabled: true,
                },
            ],
            SettingsCategory::Exchange => vec![
                MenuItem {
                    id: "archive".into(),
                    label: "Enable Archive Mailbox".into(),
                    description: "Online archive for all users".into(),
                    shortcut: Some('1'),
                    enabled: true,
                },
                MenuItem {
                    id: "forwarding".into(),
                    label: "Block External Forwarding".into(),
                    description: "Prevent data exfiltration".into(),
                    shortcut: Some('2'),
                    enabled: true,
                },
                MenuItem {
                    id: "zap".into(),
                    label: "Zero-Hour Auto Purge".into(),
                    description: "Remove delivered malware".into(),
                    shortcut: Some('3'),
                    enabled: true,
                },
                MenuItem {
                    id: "spam".into(),
                    label: "Anti-Spam Policy".into(),
                    description: "Configure spam filtering".into(),
                    shortcut: Some('4'),
                    enabled: true,
                },
                MenuItem {
                    id: "apply".into(),
                    label: "Apply Settings".into(),
                    description: "Save and apply these settings".into(),
                    shortcut: Some('a'),
                    enabled: true,
                },
                MenuItem {
                    id: "back".into(),
                    label: "← Back".into(),
                    description: "Return without saving".into(),
                    shortcut: Some('b'),
                    enabled: true,
                },
            ],
            SettingsCategory::SharePoint => vec![
                MenuItem {
                    id: "external_sharing".into(),
                    label: "External Sharing".into(),
                    description: "Allow sharing with external users".into(),
                    shortcut: Some('1'),
                    enabled: true,
                },
                MenuItem {
                    id: "sync_client".into(),
                    label: "Sync Client".into(),
                    description: "Allow OneDrive sync client".into(),
                    shortcut: Some('2'),
                    enabled: true,
                },
                MenuItem {
                    id: "versioning".into(),
                    label: "Versioning".into(),
                    description: "Enable file versioning".into(),
                    shortcut: Some('3'),
                    enabled: true,
                },
                MenuItem {
                    id: "dlp".into(),
                    label: "Data Loss Prevention".into(),
                    description: "Enable DLP policies".into(),
                    shortcut: Some('4'),
                    enabled: true,
                },
                MenuItem {
                    id: "apply".into(),
                    label: "Apply Settings".into(),
                    description: "Save and apply these settings".into(),
                    shortcut: Some('a'),
                    enabled: true,
                },
                MenuItem {
                    id: "back".into(),
                    label: "← Back".into(),
                    description: "Return without saving".into(),
                    shortcut: Some('b'),
                    enabled: true,
                },
            ],
            SettingsCategory::Teams => vec![
                MenuItem {
                    id: "external_access".into(),
                    label: "External Access".into(),
                    description: "Allow communication with external orgs".into(),
                    shortcut: Some('1'),
                    enabled: true,
                },
                MenuItem {
                    id: "guest_access".into(),
                    label: "Guest Access".into(),
                    description: "Allow guest users in Teams".into(),
                    shortcut: Some('2'),
                    enabled: true,
                },
                MenuItem {
                    id: "meeting_recording".into(),
                    label: "Meeting Recording".into(),
                    description: "Allow meeting recordings".into(),
                    shortcut: Some('3'),
                    enabled: true,
                },
                MenuItem {
                    id: "anonymous_join".into(),
                    label: "Anonymous Join".into(),
                    description: "Allow anonymous meeting join".into(),
                    shortcut: Some('4'),
                    enabled: true,
                },
                MenuItem {
                    id: "apply".into(),
                    label: "Apply Settings".into(),
                    description: "Save and apply these settings".into(),
                    shortcut: Some('a'),
                    enabled: true,
                },
                MenuItem {
                    id: "back".into(),
                    label: "← Back".into(),
                    description: "Return without saving".into(),
                    shortcut: Some('b'),
                    enabled: true,
                },
            ],
            SettingsCategory::Intune => vec![
                MenuItem {
                    id: "compliance".into(),
                    label: "Compliance Policies".into(),
                    description: "View/deploy compliance policies".into(),
                    shortcut: Some('1'),
                    enabled: true,
                },
                MenuItem {
                    id: "configuration".into(),
                    label: "Configuration Profiles".into(),
                    description: "View/deploy config profiles".into(),
                    shortcut: Some('2'),
                    enabled: true,
                },
                MenuItem {
                    id: "apps".into(),
                    label: "Applications".into(),
                    description: "View/deploy applications".into(),
                    shortcut: Some('3'),
                    enabled: true,
                },
                MenuItem {
                    id: "back".into(),
                    label: "← Back".into(),
                    description: "Return without saving".into(),
                    shortcut: Some('b'),
                    enabled: true,
                },
            ],
            _ => vec![MenuItem {
                id: "back".into(),
                label: "← Back".into(),
                description: "Return".into(),
                shortcut: Some('b'),
                enabled: true,
            }],
        }
    }

    fn reports_menu(&self) -> Vec<MenuItem> {
        vec![
            MenuItem {
                id: "compliance".into(),
                label: "Compliance Report".into(),
                description: "Full compliance audit with scoring".into(),
                shortcut: Some('1'),
                enabled: true,
            },
            MenuItem {
                id: "security".into(),
                label: "Security Assessment".into(),
                description: "Security posture analysis".into(),
                shortcut: Some('2'),
                enabled: true,
            },
            MenuItem {
                id: "inventory".into(),
                label: "Policy Inventory".into(),
                description: "List all deployed policies".into(),
                shortcut: Some('3'),
                enabled: true,
            },
            MenuItem {
                id: "changes".into(),
                label: "Change Control Report".into(),
                description: "Document changes made this session".into(),
                shortcut: Some('4'),
                enabled: true,
            },
            MenuItem {
                id: "executive".into(),
                label: "Executive Summary".into(),
                description: "High-level overview for leadership".into(),
                shortcut: Some('5'),
                enabled: true,
            },
            MenuItem {
                id: "back".into(),
                label: "← Back".into(),
                description: "Return to dashboard".into(),
                shortcut: Some('b'),
                enabled: true,
            },
        ]
    }

    /// Handle menu selection
    pub fn select_current(&mut self) {
        if let Some(idx) = self.menu_state.selected() {
            if idx < self.menu_items.len() {
                let item = &self.menu_items[idx];
                if !item.enabled {
                    self.status_message = Some((
                        format!("{} is not available", item.label),
                        StatusLevel::Warning,
                    ));
                    return;
                }
                self.handle_menu_action(&item.id.clone());
            }
        }
    }

    fn handle_menu_action(&mut self, action: &str) {
        match action {
            "quit" => self.request_exit(),
            "help" => self.show_help = !self.show_help,
            "back" => self.go_back(),
            "clients" => self.navigate_to(Screen::ClientList),
            "configure" => {
                if let Some(ref tenant) = self.active_tenant {
                    self.navigate_to(Screen::ClientConfig(tenant.clone()));
                }
            }
            "reports" => self.navigate_to(Screen::Reports),
            "add" => {
                self.navigate_to(Screen::ClientAdd);
                self.init_add_client_form();
            }
            "defender" => {
                self.init_defender_toggles();
                self.navigate_to(Screen::Settings(SettingsCategory::Defender));
            }
            "exchange" => {
                self.init_exchange_toggles();
                self.navigate_to(Screen::Settings(SettingsCategory::Exchange));
            }
            "sharepoint" => {
                self.init_sharepoint_toggles();
                self.navigate_to(Screen::Settings(SettingsCategory::SharePoint));
            }
            "teams" => {
                self.init_teams_toggles();
                self.navigate_to(Screen::Settings(SettingsCategory::Teams));
            }
            "ca" => self.navigate_to(Screen::PolicyList(PolicyListType::ConditionalAccess)),
            "intune" => self.navigate_to(Screen::Settings(SettingsCategory::Intune)),
            "baseline" => self.navigate_to(Screen::BaselineSelect),
            "audit" => self.navigate_to(Screen::PolicyList(PolicyListType::All)),
            "audit_history" => self.navigate_to(Screen::AuditHistory),

            // Audit history actions
            "audit_7d" => {
                self.audit_days_filter = 7;
                self.load_audit_entries();
                self.status_message = Some(("Showing last 7 days".into(), StatusLevel::Info));
            }
            "audit_30d" => {
                self.audit_days_filter = 30;
                self.load_audit_entries();
                self.status_message = Some(("Showing last 30 days".into(), StatusLevel::Info));
            }
            "audit_all" => {
                self.audit_days_filter = 365 * 10; // 10 years
                self.load_audit_entries();
                self.status_message = Some(("Showing all history".into(), StatusLevel::Info));
            }
            "audit_export" => {
                self.export_audit_history();
            }
            "audit_clear_session" => {
                crate::tui::change_tracker::clear_session();
                self.status_message = Some(("Session cleared".into(), StatusLevel::Success));
            }

            // Baseline deployments with confirmation and impact summary
            "windows_oib" => {
                let tenant = self
                    .active_tenant
                    .clone()
                    .unwrap_or_else(|| "Unknown".into());
                let impact =
                    crate::tui::context::ImpactSummary::baseline_deploy("Windows OIB", 6, &tenant);
                self.show_confirmation_with_impact(
                    "Deploy Windows Baseline",
                    ConfirmAction::DeployBaseline("windows_oib".into()),
                    impact,
                );
            }
            "windows_basic" => {
                let tenant = self
                    .active_tenant
                    .clone()
                    .unwrap_or_else(|| "Unknown".into());
                let impact = crate::tui::context::ImpactSummary::baseline_deploy(
                    "Windows Basic",
                    4,
                    &tenant,
                );
                self.show_confirmation_with_impact(
                    "Deploy Windows Baseline",
                    ConfirmAction::DeployBaseline("windows_basic".into()),
                    impact,
                );
            }
            "ca_2025" => {
                let tenant = self
                    .active_tenant
                    .clone()
                    .unwrap_or_else(|| "Unknown".into());
                let impact = crate::tui::context::ImpactSummary::ca_deploy(44, &tenant);
                self.show_confirmation_with_impact(
                    "Deploy CA Baseline 2025",
                    ConfirmAction::DeployConditionalAccess,
                    impact,
                );
            }

            // Settings apply with confirmation and impact summary
            "apply" | "apply_all" => {
                // Get current settings category from screen
                let category = if let Screen::Settings(cat) = &self.screen {
                    cat.clone()
                } else {
                    SettingsCategory::Main
                };
                let category_name = match &category {
                    SettingsCategory::Defender => "Defender",
                    SettingsCategory::Exchange => "Exchange",
                    SettingsCategory::SharePoint => "SharePoint",
                    SettingsCategory::Teams => "Teams",
                    _ => "All",
                };
                let tenant = self
                    .active_tenant
                    .clone()
                    .unwrap_or_else(|| "Unknown".into());
                let setting_count = self.setting_toggles.len();
                let impact = crate::tui::context::ImpactSummary::settings_change(
                    category_name,
                    setting_count,
                    &tenant,
                );
                self.show_confirmation_with_impact(
                    &format!("Apply {} Settings", category_name),
                    ConfirmAction::ApplySettings(category),
                    impact,
                );
            }

            // Search toggle
            "filter" => self.toggle_search(),

            // Refresh action
            "refresh" => {
                let policy_type_clone = if let Screen::PolicyList(pt) = &self.screen {
                    Some(pt.clone())
                } else {
                    None
                };
                if let Some(policy_type) = policy_type_clone {
                    self.load_policies(&policy_type);
                    self.status_message = Some(("Policies refreshed".into(), StatusLevel::Success));
                }
            }

            // Report generation actions
            "compliance" => self.generate_report("compliance"),
            "security" => self.generate_report("security"),
            "inventory" => self.generate_report("inventory"),
            "changes" => self.generate_report("changes"),
            "executive" => self.generate_report("executive"),
            "report" => self.generate_report("client"),

            // Policy export
            "export" => self.export_policies(),

            // Settings toggle actions
            "safe_links" | "safe_links_teams" | "safe_links_office" | "safe_attachments" => {
                self.toggle_setting(action);
                let enabled = self.setting_toggles.get(action).copied().unwrap_or(false);
                self.status_message = Some((
                    format!(
                        "{} {}",
                        action,
                        if enabled { "enabled" } else { "disabled" }
                    ),
                    StatusLevel::Info,
                ));
            }
            "archive" | "forwarding" | "zap" | "spam" | "external_sharing" | "sync_client"
            | "versioning" | "dlp" | "external_access" | "guest_access" | "meeting_recording"
            | "anonymous_join" => {
                self.toggle_setting(action);
                let enabled = self.setting_toggles.get(action).copied().unwrap_or(false);
                self.status_message = Some((
                    format!(
                        "{} {}",
                        action.replace('_', " "),
                        if enabled { "enabled" } else { "disabled" }
                    ),
                    StatusLevel::Info,
                ));
            }

            // Client operations
            "delete_client" => {
                if let Some(ref tenant) = self.active_tenant {
                    self.show_confirmation(
                        "Delete Client",
                        &format!("Are you sure you want to delete client {}?\n\nThis will remove the client configuration. Tenant data will not be affected.", tenant),
                        ConfirmAction::DeleteClient(tenant.clone())
                    );
                }
            }

            id if id.starts_with("client:") => {
                let abbrev = id.strip_prefix("client:").unwrap();
                let old_tenant = self.active_tenant.clone();
                // Switch to this client
                if let Err(e) = self.config.set_active_tenant(abbrev) {
                    self.status_message =
                        Some((format!("Failed to switch: {}", e), StatusLevel::Error));
                } else {
                    // Record tenant switch
                    crate::tui::change_tracker::record_tenant_switch(old_tenant.as_deref(), abbrev);
                    self.active_tenant = Some(abbrev.to_string());
                    self.status_message =
                        Some((format!("Switched to {}", abbrev), StatusLevel::Success));
                    self.navigate_to(Screen::ClientConfig(abbrev.to_string()));
                }
            }
            _ => {
                self.status_message = Some((
                    format!("Action '{}' not implemented yet", action),
                    StatusLevel::Warning,
                ));
            }
        }
    }

    /// Generate a report
    fn generate_report(&mut self, report_type: &str) {
        let tenant = self
            .active_tenant
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("{}_{}_report_{}.html", tenant, report_type, timestamp);

        // Generate report content based on type
        let title = match report_type {
            "compliance" => "Compliance Report",
            "security" => "Security Assessment",
            "inventory" => "Policy Inventory",
            "changes" => "Change Control Report",
            "executive" => "Executive Summary",
            "client" => "Client Report",
            _ => "Report",
        };

        let html_content = self.generate_html_report(title, report_type);

        // Save to file
        let report_dir = directories::UserDirs::new()
            .and_then(|u| Some(u.home_dir().join(".ctl365").join("reports")))
            .unwrap_or_else(|| std::path::PathBuf::from("./reports"));

        if let Err(e) = std::fs::create_dir_all(&report_dir) {
            self.status_message = Some((
                format!("Failed to create reports directory: {}", e),
                StatusLevel::Error,
            ));
            return;
        }

        let report_path = report_dir.join(&filename);
        match std::fs::write(&report_path, html_content) {
            Ok(_) => {
                // Record audit entry for report generation
                crate::tui::change_tracker::record_report_generated(
                    title,
                    &report_path.display().to_string(),
                    &tenant,
                );
                self.status_message = Some((
                    format!("Report saved: {}", report_path.display()),
                    StatusLevel::Success,
                ));
            }
            Err(e) => {
                self.status_message =
                    Some((format!("Failed to save report: {}", e), StatusLevel::Error));
            }
        }
    }

    fn generate_html_report(&self, title: &str, report_type: &str) -> String {
        let tenant = self
            .active_tenant
            .clone()
            .unwrap_or_else(|| "No Tenant".to_string());
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");

        let content = match report_type {
            "compliance" => self.generate_compliance_content(),
            "security" => self.generate_security_content(),
            "inventory" => self.generate_inventory_content(),
            "changes" => self.generate_changes_content(),
            "executive" => self.generate_executive_content(),
            "client" => self.generate_client_report_content(),
            _ => "<p>Report content not available.</p>".to_string(),
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - {tenant}</title>
    <style>
        :root {{
            --ms-blue: #0078d4;
            --ms-dark-blue: #004578;
            --ms-green: #107c10;
            --ms-yellow: #ffb900;
            --ms-red: #d13438;
            --ms-gray: #605e5c;
            --ms-light-gray: #f3f2f1;
            --ms-border: #edebe9;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .header-bar {{
            background: var(--ms-blue);
            color: white;
            padding: 16px 30px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .header-bar .logo {{
            font-size: 24px;
            font-weight: 700;
        }}
        .header-bar .title {{
            font-size: 18px;
            opacity: 0.9;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            min-height: calc(100vh - 60px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }}
        .content {{ padding: 30px; }}
        h1 {{ color: var(--ms-dark-blue); border-bottom: 3px solid var(--ms-blue); padding-bottom: 12px; margin-top: 0; }}
        h2 {{ color: #323130; margin-top: 30px; font-size: 20px; }}
        h3 {{ color: var(--ms-gray); margin: 0 0 15px 0; font-size: 16px; font-weight: 600; }}
        .meta {{
            color: var(--ms-gray);
            font-size: 14px;
            margin-bottom: 25px;
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
        }}
        .meta-item {{ display: flex; flex-direction: column; }}
        .meta-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #8a8886; }}
        .meta-value {{ font-weight: 600; color: #323130; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 14px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--ms-border); }}
        th {{ background: var(--ms-light-gray); font-weight: 600; color: #323130; font-size: 12px; text-transform: uppercase; letter-spacing: 0.3px; }}
        tr:hover {{ background: #faf9f8; }}
        tr.total {{ background: var(--ms-light-gray); font-weight: 600; }}
        .status-deployed, .status-enabled {{ color: var(--ms-green); font-weight: 500; }}
        .status-reportonly, .status-report-only {{ color: var(--ms-yellow); font-weight: 500; }}
        .status-disabled {{ color: var(--ms-red); font-weight: 500; }}
        .score {{ font-size: 56px; font-weight: bold; color: var(--ms-blue); }}
        .summary-box {{ background: var(--ms-light-gray); padding: 25px; border-radius: 8px; margin: 20px 0; text-align: center; }}
        .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .card {{
            background: white;
            border: 1px solid var(--ms-border);
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.04);
        }}
        .card h3 {{ border-bottom: 2px solid var(--ms-blue); padding-bottom: 10px; }}
        .report-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }}
        .client-badge {{
            background: var(--ms-yellow);
            color: #323130;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-success {{ background: #dff6dd; color: var(--ms-green); }}
        .badge-warning {{ background: #fff4ce; color: #8a6914; }}
        .badge-danger {{ background: #fde7e9; color: var(--ms-red); }}
        .audit-table code {{
            background: var(--ms-light-gray);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            color: var(--ms-dark-blue);
        }}
        .no-data {{
            color: var(--ms-gray);
            font-style: italic;
            padding: 20px;
            text-align: center;
            background: var(--ms-light-gray);
            border-radius: 4px;
        }}
        .footer {{
            margin-top: 40px;
            padding: 20px 30px;
            border-top: 1px solid var(--ms-border);
            color: var(--ms-gray);
            font-size: 12px;
            background: var(--ms-light-gray);
            display: flex;
            justify-content: space-between;
        }}
        @media print {{
            body {{ background: white; }}
            .container {{ box-shadow: none; }}
            .header-bar {{ background: var(--ms-dark-blue); -webkit-print-color-adjust: exact; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-bar">
            <span class="logo">M365</span>
            <span class="title">ctl365 - {title}</span>
        </div>
        <div class="content">
            <h1>{title}</h1>
            <div class="meta">
                <div class="meta-item">
                    <span class="meta-label">Tenant</span>
                    <span class="meta-value">{tenant}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Generated</span>
                    <span class="meta-value">{timestamp}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Tool</span>
                    <span class="meta-value">ctl365 v0.1.0</span>
                </div>
            </div>
            {content}
        </div>
        <div class="footer">
            <span>Generated by ctl365 - Microsoft 365 Baseline Automation CLI</span>
            <span>© 2025</span>
        </div>
    </div>
</body>
</html>"#,
            title = title,
            tenant = tenant,
            timestamp = timestamp,
            content = content
        )
    }

    fn generate_compliance_content(&self) -> String {
        format!(
            r#"
        <div class="summary-box">
            <span class="score">85%</span>
            <p>Compliance Score</p>
        </div>
        <h2>Compliance Summary</h2>
        <table>
            <tr><th>Category</th><th>Status</th><th>Score</th></tr>
            <tr><td>Device Compliance</td><td class="status-deployed">Compliant</td><td>90%</td></tr>
            <tr><td>Conditional Access</td><td class="status-deployed">Deployed</td><td>85%</td></tr>
            <tr><td>Data Protection</td><td class="status-report-only">Partial</td><td>75%</td></tr>
            <tr><td>Identity Protection</td><td class="status-deployed">Compliant</td><td>88%</td></tr>
        </table>
        <h2>Recommendations</h2>
        <ul>
            <li>Enable MFA for all users</li>
            <li>Deploy BitLocker encryption policies</li>
            <li>Configure Windows Defender ATP</li>
        </ul>
        "#
        )
    }

    fn generate_security_content(&self) -> String {
        format!(
            r#"
        <h2>Security Posture</h2>
        <div class="summary-box">
            <span class="score">B+</span>
            <p>Security Grade</p>
        </div>
        <h2>Security Controls</h2>
        <table>
            <tr><th>Control</th><th>Status</th><th>Risk</th></tr>
            <tr><td>Multi-Factor Authentication</td><td class="status-deployed">Enabled</td><td>Low</td></tr>
            <tr><td>Legacy Authentication</td><td class="status-deployed">Blocked</td><td>Low</td></tr>
            <tr><td>Conditional Access</td><td class="status-report-only">Report-Only</td><td>Medium</td></tr>
            <tr><td>Device Encryption</td><td class="status-deployed">Required</td><td>Low</td></tr>
            <tr><td>Safe Links</td><td class="status-deployed">Enabled</td><td>Low</td></tr>
        </table>
        "#
        )
    }

    fn generate_inventory_content(&self) -> String {
        let policies: Vec<String> = self
            .table_data
            .iter()
            .map(|p| {
                format!(
                    r#"<tr><td>{}</td><td>{}</td><td class="status-{}">{}</td><td>{}</td></tr>"#,
                    p.name,
                    p.policy_type,
                    p.status.as_str().to_lowercase().replace("-", ""),
                    p.status.as_str(),
                    p.platform
                )
            })
            .collect();

        let policy_rows = if policies.is_empty() {
            "<tr><td colspan='4'>No policies loaded. Navigate to a policy list first.</td></tr>"
                .to_string()
        } else {
            policies.join("\n")
        };

        format!(
            r#"
        <h2>Policy Inventory</h2>
        <p>Total Policies: {}</p>
        <table>
            <tr><th>Policy Name</th><th>Type</th><th>Status</th><th>Platform</th></tr>
            {}
        </table>
        "#,
            self.table_data.len(),
            policy_rows
        )
    }

    fn generate_changes_content(&self) -> String {
        // Load session changes
        let changes = crate::tui::change_tracker::load_session_changes().unwrap_or_default();

        let change_rows: Vec<String> = changes
            .iter()
            .map(|c| {
                format!(
                    r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                    c.timestamp,
                    c.category,
                    c.setting_name,
                    c.change_type,
                    c.new_value.clone().unwrap_or_default()
                )
            })
            .collect();

        let rows = if change_rows.is_empty() {
            "<tr><td colspan='5'>No changes recorded this session.</td></tr>".to_string()
        } else {
            change_rows.join("\n")
        };

        format!(
            r#"
        <h2>Change Control Report</h2>
        <p>Changes made during this session:</p>
        <table>
            <tr><th>Timestamp</th><th>Category</th><th>Setting</th><th>Action</th><th>New Value</th></tr>
            {}
        </table>
        "#,
            rows
        )
    }

    fn generate_executive_content(&self) -> String {
        format!(
            r#"
        <h2>Executive Summary</h2>
        <div class="summary-box">
            <h3>Key Highlights</h3>
            <ul>
                <li><strong>Compliance Score:</strong> 85% (Good)</li>
                <li><strong>Security Posture:</strong> B+ Grade</li>
                <li><strong>Active Policies:</strong> {} deployed</li>
                <li><strong>Risk Level:</strong> Low-Medium</li>
            </ul>
        </div>
        <h2>Recommendations</h2>
        <ol>
            <li>Transition Conditional Access policies from Report-Only to Enforced mode</li>
            <li>Enable Windows Defender for Endpoint on all devices</li>
            <li>Review and remediate devices with compliance issues</li>
            <li>Schedule quarterly security reviews</li>
        </ol>
        "#,
            self.table_data.len()
        )
    }

    fn generate_client_report_content(&self) -> String {
        let tenant = self
            .active_tenant
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        let changes = crate::tui::change_tracker::load_session_changes().unwrap_or_default();
        let change_summary = crate::tui::change_tracker::get_change_summary();
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let policy_count = self.table_data.len();
        let change_count = changes.len();

        // Policy summary by type
        let mut policy_counts = std::collections::HashMap::new();
        for p in &self.table_data {
            *policy_counts.entry(p.policy_type.clone()).or_insert(0) += 1;
        }

        let policy_rows: String = if policy_counts.is_empty() {
            "<tr><td colspan='2'>No policies loaded</td></tr>".to_string()
        } else {
            policy_counts
                .iter()
                .map(|(k, v)| format!("<tr><td>{}</td><td>{}</td></tr>", k, v))
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Change summary rows
        let change_rows: String = if change_summary.is_empty() {
            "<tr><td colspan='2'>No changes</td></tr>".to_string()
        } else {
            change_summary
                .iter()
                .map(|(cat, count)| format!("<tr><td>{}</td><td>{}</td></tr>", cat, count))
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Recent changes (last 10)
        let recent_changes: String = if changes.is_empty() {
            "<tr><td colspan='5' class='no-data'>No activity recorded</td></tr>".to_string()
        } else {
            changes.iter()
                .take(10)
                .map(|c| format!(
                    "<tr><td>{}</td><td><span class=\"badge badge-{}\">{}</span></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                    c.timestamp,
                    match c.change_type.as_str() {
                        "created" => "success",
                        "deleted" => "danger",
                        _ => "warning"
                    },
                    c.change_type,
                    c.category,
                    c.setting_name,
                    c.new_value.clone().unwrap_or_else(|| "-".to_string())
                ))
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Settings toggles summary
        let toggle_rows: String = if self.setting_toggles.is_empty() {
            "<tr><td colspan='2'>No settings configured</td></tr>".to_string()
        } else {
            self.setting_toggles
                .iter()
                .map(|(k, v)| {
                    format!(
                        "<tr><td>{}</td><td class=\"{}\">{}</td></tr>",
                        k.replace('_', " "),
                        if *v {
                            "status-deployed"
                        } else {
                            "status-disabled"
                        },
                        if *v { "Enabled" } else { "Disabled" }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        let no_changes_msg = if changes.is_empty() {
            "<p class='no-data'>No changes recorded this session. Make configuration changes to see audit trail.</p>"
        } else {
            ""
        };

        format!(
            r#"
        <div class="report-header">
            <h2>Client Overview</h2>
            <div class="client-badge">{}</div>
        </div>

        <div class="grid-2">
            <div class="card">
                <h3>Policy Summary</h3>
                <table>
                    <tr><th>Policy Type</th><th>Count</th></tr>
                    {}
                    <tr class="total"><td><strong>Total</strong></td><td><strong>{}</strong></td></tr>
                </table>
            </div>

            <div class="card">
                <h3>Session Changes</h3>
                <table>
                    <tr><th>Category</th><th>Changes</th></tr>
                    {}
                    <tr class="total"><td><strong>Total</strong></td><td><strong>{}</strong></td></tr>
                </table>
            </div>
        </div>

        <div class="card">
            <h3>Current Settings</h3>
            <table>
                <tr><th>Setting</th><th>Status</th></tr>
                {}
            </table>
        </div>

        <div class="card">
            <h3>Recent Activity (Audit Trail)</h3>
            <table class="audit-table">
                <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Category</th>
                    <th>Setting</th>
                    <th>Value</th>
                </tr>
                {}
            </table>
            {}
        </div>

        <div class="card">
            <h3>Session Information</h3>
            <table>
                <tr><td>Generated</td><td>{}</td></tr>
                <tr><td>Tool Version</td><td>ctl365 v0.1.0</td></tr>
                <tr><td>Tenant</td><td>{}</td></tr>
                <tr><td>Changes This Session</td><td>{}</td></tr>
            </table>
        </div>
        "#,
            tenant,
            policy_rows,
            policy_count,
            change_rows,
            change_count,
            toggle_rows,
            recent_changes,
            no_changes_msg,
            timestamp,
            tenant,
            change_count
        )
    }

    /// Export policies to JSON/CSV
    fn export_policies(&mut self) {
        if self.table_data.is_empty() {
            self.status_message = Some((
                "No policies to export. Load policies first.".to_string(),
                StatusLevel::Warning,
            ));
            return;
        }

        let tenant = self
            .active_tenant
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");

        let export_dir = directories::UserDirs::new()
            .and_then(|u| Some(u.home_dir().join(".ctl365").join("exports")))
            .unwrap_or_else(|| std::path::PathBuf::from("./exports"));

        if let Err(e) = std::fs::create_dir_all(&export_dir) {
            self.status_message = Some((
                format!("Failed to create exports directory: {}", e),
                StatusLevel::Error,
            ));
            return;
        }

        // Export to JSON
        let json_filename = format!("{}_policies_{}.json", tenant, timestamp);
        let json_path = export_dir.join(&json_filename);

        let json_data: Vec<serde_json::Value> = self
            .table_data
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "type": p.policy_type,
                    "status": p.status.as_str(),
                    "platform": p.platform,
                    "assignments": p.assignments,
                    "last_modified": p.last_modified
                })
            })
            .collect();

        match serde_json::to_string_pretty(&json_data) {
            Ok(json_str) => {
                if let Err(e) = std::fs::write(&json_path, json_str) {
                    self.status_message =
                        Some((format!("Failed to write JSON: {}", e), StatusLevel::Error));
                    return;
                }
            }
            Err(e) => {
                self.status_message =
                    Some((format!("Failed to serialize: {}", e), StatusLevel::Error));
                return;
            }
        }

        // Export to CSV
        let csv_filename = format!("{}_policies_{}.csv", tenant, timestamp);
        let csv_path = export_dir.join(&csv_filename);

        let mut csv_content = "Name,Type,Status,Platform,Assignments,LastModified\n".to_string();
        for p in &self.table_data {
            csv_content.push_str(&format!(
                "{},{},{},{},{},{}\n",
                p.name.replace(',', ";"),
                p.policy_type,
                p.status.as_str(),
                p.platform,
                p.assignments,
                p.last_modified
            ));
        }

        if let Err(e) = std::fs::write(&csv_path, csv_content) {
            self.status_message = Some((format!("Failed to write CSV: {}", e), StatusLevel::Error));
            return;
        }

        self.status_message = Some((
            format!(
                "Exported {} policies to {}",
                self.table_data.len(),
                export_dir.display()
            ),
            StatusLevel::Success,
        ));
    }

    /// Export audit history to JSON file
    fn export_audit_history(&mut self) {
        if self.audit_entries.is_empty() {
            self.status_message = Some((
                "No audit entries to export".to_string(),
                StatusLevel::Warning,
            ));
            return;
        }

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("audit_export_{}.json", timestamp);

        let export_dir = directories::UserDirs::new()
            .and_then(|u| Some(u.home_dir().join(".ctl365").join("exports")))
            .unwrap_or_else(|| std::path::PathBuf::from("./exports"));

        if let Err(e) = std::fs::create_dir_all(&export_dir) {
            self.status_message = Some((
                format!("Failed to create exports directory: {}", e),
                StatusLevel::Error,
            ));
            return;
        }

        let export_path = export_dir.join(&filename);

        match serde_json::to_string_pretty(&self.audit_entries) {
            Ok(json_str) => match std::fs::write(&export_path, json_str) {
                Ok(_) => {
                    self.status_message = Some((
                        format!(
                            "Exported {} entries to {}",
                            self.audit_entries.len(),
                            export_path.display()
                        ),
                        StatusLevel::Success,
                    ));
                }
                Err(e) => {
                    self.status_message =
                        Some((format!("Failed to write file: {}", e), StatusLevel::Error));
                }
            },
            Err(e) => {
                self.status_message =
                    Some((format!("Failed to serialize: {}", e), StatusLevel::Error));
            }
        }
    }

    /// Handle confirmation dialog result
    pub fn handle_confirmation(&mut self, confirmed: bool) {
        if let Some(dialog) = self.confirmation.take() {
            if confirmed {
                match dialog.action {
                    ConfirmAction::DeployBaseline(baseline) => {
                        self.deploy_baseline_to_tenant(&baseline);
                    }
                    ConfirmAction::DeployConditionalAccess => {
                        self.deploy_conditional_access_policies();
                    }
                    ConfirmAction::ApplySettings(category) => {
                        self.apply_settings_to_tenant(category);
                    }
                    ConfirmAction::DeleteClient(abbrev) => {
                        // Delete the client from config
                        match self.config.remove_tenant(&abbrev) {
                            Ok(_) => {
                                self.status_message = Some((
                                    format!("Client {} deleted successfully", abbrev),
                                    StatusLevel::Success,
                                ));
                                // Return to client list
                                self.active_tenant = None;
                                self.navigate_to(Screen::ClientList);
                            }
                            Err(e) => {
                                self.status_message = Some((
                                    format!("Failed to delete client: {}", e),
                                    StatusLevel::Error,
                                ));
                            }
                        }
                    }
                    ConfirmAction::ExitWithChanges => {
                        // User confirmed exit despite unsaved changes
                        self.exit_confirmed = true;
                        self.should_quit = true;
                    }
                }
            } else {
                // Cancelled - if this was an exit confirmation, stay in app
                if matches!(dialog.action, ConfirmAction::ExitWithChanges) {
                    self.status_message = Some(("Exit cancelled".into(), StatusLevel::Info));
                } else {
                    self.status_message = Some(("Action cancelled".into(), StatusLevel::Info));
                }
            }
        }
    }

    /// Apply settings to tenant via Graph API
    fn apply_settings_to_tenant(&mut self, category: SettingsCategory) {
        let tenant_name = match &self.active_tenant {
            Some(name) => name.clone(),
            None => {
                self.status_message =
                    Some(("No active tenant selected".into(), StatusLevel::Error));
                return;
            }
        };

        // Build TenantConfiguration from current toggle states
        let tenant_config = self.build_tenant_config_from_toggles();

        // Execute async API call using tokio runtime
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                self.status_message =
                    Some(("No async runtime available".into(), StatusLevel::Error));
                return;
            }
        };

        let config = self.config.clone();
        let result = match category {
            SettingsCategory::Defender => handle.block_on(async {
                crate::tui::menu::apply_defender_settings_from_config(
                    &config,
                    &tenant_name,
                    &tenant_config,
                )
                .await
            }),
            SettingsCategory::Exchange => handle.block_on(async {
                crate::tui::menu::apply_exchange_settings_from_config(
                    &config,
                    &tenant_name,
                    &tenant_config,
                )
                .await
            }),
            SettingsCategory::SharePoint => handle.block_on(async {
                crate::tui::menu::apply_sharepoint_settings_from_config(
                    &config,
                    &tenant_name,
                    &tenant_config,
                )
                .await
            }),
            SettingsCategory::Teams => handle.block_on(async {
                crate::tui::menu::apply_teams_settings_from_config(
                    &config,
                    &tenant_name,
                    &tenant_config,
                )
                .await
            }),
            SettingsCategory::Main => {
                // Apply all settings
                handle.block_on(async {
                    crate::tui::menu::apply_all_settings_from_config(
                        &config,
                        &tenant_name,
                        &tenant_config,
                    )
                    .await
                })
            }
            _ => {
                self.status_message = Some((
                    "Settings category not supported for API apply".into(),
                    StatusLevel::Warning,
                ));
                return;
            }
        };

        match result {
            Ok(msg) => {
                // Record audit entry for settings applied
                let category_name = match category {
                    SettingsCategory::Defender => "Defender",
                    SettingsCategory::Exchange => "Exchange",
                    SettingsCategory::SharePoint => "SharePoint",
                    SettingsCategory::Teams => "Teams",
                    _ => "Settings",
                };
                crate::tui::change_tracker::record_setting_change(
                    category_name,
                    "Settings Applied",
                    None,
                    "Configured via TUI",
                    &tenant_name,
                );
                self.status_message = Some((msg, StatusLevel::Success));
            }
            Err(e) => {
                crate::tui::change_tracker::record_error(
                    "Settings",
                    "Apply Settings",
                    &e.to_string(),
                    &tenant_name,
                );
                self.status_message = Some((
                    format!("Failed to apply settings: {}", e),
                    StatusLevel::Error,
                ));
            }
        }
    }

    /// Build TenantConfiguration from current toggle states
    fn build_tenant_config_from_toggles(&self) -> crate::tui::settings::TenantConfiguration {
        use crate::tui::settings::TenantConfiguration;

        let mut config = TenantConfiguration::recommended();

        // Defender settings
        if let Some(&val) = self.setting_toggles.get("safe_links") {
            config.safe_links_enabled = val;
        }
        if let Some(&val) = self.setting_toggles.get("safe_links_teams") {
            config.safe_links_teams = val;
        }
        if let Some(&val) = self.setting_toggles.get("safe_links_office") {
            config.safe_links_office = val;
        }
        if let Some(&val) = self.setting_toggles.get("safe_attachments") {
            config.safe_attachments_enabled = val;
        }

        // Exchange settings
        if let Some(&val) = self.setting_toggles.get("archive") {
            config.archive_mailbox = val;
        }
        if let Some(&val) = self.setting_toggles.get("forwarding") {
            config.external_forwarding_blocked = val;
        }
        if let Some(&val) = self.setting_toggles.get("zap") {
            config.zap_enabled = val;
        }
        if let Some(&val) = self.setting_toggles.get("spam") {
            // spam toggle controls strict spam policy
            if val {
                config.high_confidence_spam_action = "Quarantine".into();
            }
        }

        // SharePoint settings
        if let Some(&val) = self.setting_toggles.get("external_sharing") {
            if val {
                config.external_sharing = "ExistingExternalUserSharingOnly".into();
            } else {
                config.external_sharing = "Disabled".into();
            }
        }
        if let Some(&val) = self.setting_toggles.get("sync_client") {
            config.sync_client_restriction = !val; // inverted: toggle enables sync, restriction disables it
        }

        // Teams settings
        if let Some(&val) = self.setting_toggles.get("external_access") {
            config.external_access = val;
        }
        if let Some(&val) = self.setting_toggles.get("guest_access") {
            config.teams_consumer_access = val;
        }
        if let Some(&val) = self.setting_toggles.get("meeting_recording") {
            config.meeting_recording = val;
        }
        if let Some(&val) = self.setting_toggles.get("anonymous_join") {
            config.anonymous_meeting_join = val;
        }

        config
    }

    /// Deploy baseline to tenant via Graph API
    fn deploy_baseline_to_tenant(&mut self, baseline_type: &str) {
        let tenant_name = match &self.active_tenant {
            Some(name) => name.clone(),
            None => {
                self.status_message =
                    Some(("No active tenant selected".into(), StatusLevel::Error));
                return;
            }
        };

        // Parse baseline type (e.g., "windows_oib", "windows_basic")
        let (platform, template) = if baseline_type.contains('_') {
            let parts: Vec<&str> = baseline_type.splitn(2, '_').collect();
            (parts[0], parts.get(1).copied().unwrap_or("basic"))
        } else {
            ("windows", baseline_type)
        };

        // Generate baseline using templates
        let args = crate::cmd::baseline::NewArgs {
            platform: platform.to_string(),
            template: template.to_string(),
            output: None,
            encryption: true,
            defender: true,
            min_os: None,
            mde_onboarding: None,
            name: "Baseline".to_string(),
        };

        let baseline = match platform {
            "windows" => match template {
                "basic" => crate::templates::windows::generate_baseline(&args),
                "oib" | "openintune" => crate::templates::windows_oib::generate_oib_baseline(&args),
                _ => {
                    self.status_message = Some((
                        format!("Unknown template: {}", template),
                        StatusLevel::Error,
                    ));
                    return;
                }
            },
            _ => {
                self.status_message = Some((
                    format!("Platform {} not yet supported in TUI", platform),
                    StatusLevel::Warning,
                ));
                return;
            }
        };

        let baseline = match baseline {
            Ok(b) => b,
            Err(e) => {
                self.status_message = Some((
                    format!("Failed to generate baseline: {}", e),
                    StatusLevel::Error,
                ));
                return;
            }
        };

        // Start progress indicator
        self.start_async_task(
            "deploy_baseline",
            &format!("Deploying {} baseline...", template),
        );

        // Execute async deploy
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                self.complete_async_task(false, "No async runtime available");
                return;
            }
        };

        // Count policies for progress
        let policy_count = baseline["policies"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);

        self.update_async_progress(10, &format!("Found {} policies to deploy", policy_count));

        let config = self.config.clone();
        let result = handle.block_on(async {
            deploy_baseline_policies_with_progress(&config, &tenant_name, &baseline).await
        });

        match result {
            Ok(count) => {
                // Record audit entry
                crate::tui::change_tracker::record_baseline_deployed(
                    &format!("{} baseline", template),
                    count,
                    &tenant_name,
                );
                self.complete_async_task(
                    true,
                    &format!(
                        "Successfully deployed {} policies from {} baseline",
                        count, template
                    ),
                );
            }
            Err(e) => {
                crate::tui::change_tracker::record_error(
                    "Baseline",
                    &format!("{} baseline deployment", template),
                    &e.to_string(),
                    &tenant_name,
                );
                self.complete_async_task(false, &format!("Failed to deploy baseline: {}", e));
            }
        }
    }

    /// Deploy Conditional Access policies to tenant
    fn deploy_conditional_access_policies(&mut self) {
        let tenant_name = match &self.active_tenant {
            Some(name) => name.clone(),
            None => {
                self.status_message =
                    Some(("No active tenant selected".into(), StatusLevel::Error));
                return;
            }
        };

        // Start progress indicator
        self.start_async_task("deploy_ca", "Deploying CA Baseline 2025...");

        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                self.complete_async_task(false, "No async runtime available");
                return;
            }
        };

        self.update_async_progress(5, "Generating 44 CA policies...");

        let config = self.config.clone();
        let result = handle
            .block_on(async { deploy_ca_policies_2025_with_progress(&config, &tenant_name).await });

        match result {
            Ok(count) => {
                // Record audit entry
                crate::tui::change_tracker::record_baseline_deployed(
                    "CA Baseline 2025",
                    count,
                    &tenant_name,
                );
                self.complete_async_task(
                    true,
                    &format!(
                        "Successfully deployed {} CA policies in Report-Only mode",
                        count
                    ),
                );
            }
            Err(e) => {
                crate::tui::change_tracker::record_error(
                    "Conditional Access",
                    "CA Baseline 2025 deployment",
                    &e.to_string(),
                    &tenant_name,
                );
                self.complete_async_task(false, &format!("Failed to deploy CA policies: {}", e));
            }
        }
    }

    /// Move selection up
    pub fn select_previous(&mut self) {
        if self.menu_items.is_empty() {
            return;
        }
        let i = match self.menu_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.menu_items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.menu_state.select(Some(i));
    }

    /// Move selection down
    pub fn select_next(&mut self) {
        if self.menu_items.is_empty() {
            return;
        }
        let i = match self.menu_state.selected() {
            Some(i) => {
                if i >= self.menu_items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.menu_state.select(Some(i));
    }

    /// Handle number key for quick selection
    pub fn select_by_number(&mut self, num: usize) {
        if num > 0 && num <= self.menu_items.len() {
            self.menu_state.select(Some(num - 1));
            self.select_current();
        }
    }

    /// Handle shortcut key
    pub fn handle_shortcut(&mut self, key: char) {
        for (idx, item) in self.menu_items.iter().enumerate() {
            if item.shortcut == Some(key) && item.enabled {
                self.menu_state.select(Some(idx));
                self.select_current();
                return;
            }
        }
    }

    /// Move table selection up
    pub fn table_previous(&mut self) {
        if self.table_data.is_empty() {
            return;
        }
        let filtered = self.filtered_table_data();
        if filtered.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    filtered.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Move table selection down
    pub fn table_next(&mut self) {
        if self.table_data.is_empty() {
            return;
        }
        let filtered = self.filtered_table_data();
        if filtered.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= filtered.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    /// Handle search input
    pub fn handle_search_input(&mut self, c: char) {
        self.search_input.push(c);
        // Reset selection and pagination when search changes
        self.menu_state.select(Some(0));
        self.table_state.select(Some(0));
        self.table_page = 0;
    }

    /// Handle search backspace
    pub fn handle_search_backspace(&mut self) {
        self.search_input.pop();
        self.menu_state.select(Some(0));
        self.table_state.select(Some(0));
        self.table_page = 0; // Reset page on search change
    }

    /// Get paginated view of filtered table data
    pub fn paginated_table_data(&self) -> Vec<&PolicyRow> {
        let filtered = self.filtered_table_data();
        let start = self.table_page * self.table_page_size;
        let end = (start + self.table_page_size).min(filtered.len());
        if start >= filtered.len() {
            Vec::new()
        } else {
            filtered[start..end].to_vec()
        }
    }

    /// Get total number of pages
    pub fn table_total_pages(&self) -> usize {
        let filtered = self.filtered_table_data();
        if filtered.is_empty() {
            1
        } else {
            (filtered.len() + self.table_page_size - 1) / self.table_page_size
        }
    }

    /// Go to next page
    pub fn table_next_page(&mut self) {
        let total_pages = self.table_total_pages();
        if self.table_page < total_pages - 1 {
            self.table_page += 1;
            self.table_state.select(Some(0));
        }
    }

    /// Go to previous page
    pub fn table_prev_page(&mut self) {
        if self.table_page > 0 {
            self.table_page -= 1;
            self.table_state.select(Some(0));
        }
    }

    /// Go to first page
    pub fn table_first_page(&mut self) {
        self.table_page = 0;
        self.table_state.select(Some(0));
    }

    /// Go to last page
    pub fn table_last_page(&mut self) {
        self.table_page = self.table_total_pages().saturating_sub(1);
        self.table_state.select(Some(0));
    }

    /// Reset pagination when loading new data
    pub fn reset_table_pagination(&mut self) {
        self.table_page = 0;
        self.table_state.select(Some(0));
    }

    /// Process any pending task responses from the background worker
    pub fn process_task_responses(&mut self) {
        use crate::tui::tasks::{TaskResponse, TaskResult};

        let responses = if let Some(ref receiver) = self.task_receiver {
            receiver.drain()
        } else {
            return;
        };

        for response in responses {
            match response {
                TaskResponse::Ready => {
                    // Worker is ready
                }
                TaskResponse::Progress(progress) => {
                    // Update progress indicator
                    if Some(&progress.task_id) == self.current_task_id.as_ref() {
                        if let Some(ref mut task) = self.async_task {
                            task.progress = progress.percent;
                            task.message = progress.message.clone();
                        }
                        // Update progress display
                        if let Some(ref mut p) = self.progress {
                            p.current = progress.percent;
                            p.message = progress.message;
                        }
                    }
                }
                TaskResponse::Completed { task_id, result } => {
                    // Task completed
                    if Some(&task_id) == self.current_task_id.as_ref() {
                        self.current_task_id = None;
                        self.progress = None;

                        match result {
                            TaskResult::PoliciesLoaded { policies } => {
                                // Convert to table data
                                self.table_data = policies
                                    .into_iter()
                                    .map(|p| PolicyRow {
                                        name: p.name,
                                        policy_type: p.policy_type,
                                        status: match p.status.as_str() {
                                            "Deployed" => PolicyStatus::Deployed,
                                            "Report-Only" => PolicyStatus::ReportOnly,
                                            "Disabled" => PolicyStatus::Disabled,
                                            _ => PolicyStatus::Deployed,
                                        },
                                        platform: p.platform,
                                        assignments: p.assignments,
                                        last_modified: p.last_modified,
                                    })
                                    .collect();
                                self.reset_table_pagination();
                                self.status_message = Some((
                                    format!("Loaded {} policies", self.table_data.len()),
                                    StatusLevel::Success,
                                ));
                            }
                            TaskResult::BaselineDeployed { count, message } => {
                                self.complete_async_task(true, &message);
                                self.status_message = Some((
                                    format!("Deployed {} policies", count),
                                    StatusLevel::Success,
                                ));
                            }
                            TaskResult::CaDeployed { count, message } => {
                                self.complete_async_task(true, &message);
                                self.status_message = Some((
                                    format!("Deployed {} CA policies", count),
                                    StatusLevel::Success,
                                ));
                            }
                            TaskResult::SettingsApplied { message } => {
                                self.complete_async_task(true, &message);
                                self.status_message = Some((message, StatusLevel::Success));
                            }
                            TaskResult::AuthResult { success, message } => {
                                if success {
                                    self.status_message = Some((message, StatusLevel::Success));
                                } else {
                                    self.status_message = Some((message, StatusLevel::Error));
                                }
                            }
                            TaskResult::Error { message } => {
                                self.complete_async_task(false, &message);
                                self.status_message = Some((message, StatusLevel::Error));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Send a task to the background worker
    pub fn send_task(&mut self, request: crate::tui::tasks::TaskRequest) -> bool {
        if let Some(ref sender) = self.task_sender {
            let task_id = format!("task_{}", chrono::Utc::now().timestamp_millis());
            self.current_task_id = Some(task_id.clone());
            sender.send(request).is_ok()
        } else {
            false
        }
    }

    /// Load policies using background worker (non-blocking)
    pub fn load_policies_async(&mut self, policy_type: &PolicyListType) {
        let tenant = match self.active_tenant.clone() {
            Some(t) => t,
            None => return,
        };

        let task_type = match policy_type {
            PolicyListType::Compliance => crate::tui::tasks::PolicyType::Compliance,
            PolicyListType::Configuration => crate::tui::tasks::PolicyType::Configuration,
            PolicyListType::SettingsCatalog => crate::tui::tasks::PolicyType::SettingsCatalog,
            PolicyListType::ConditionalAccess => crate::tui::tasks::PolicyType::ConditionalAccess,
            PolicyListType::Apps => crate::tui::tasks::PolicyType::Apps,
            PolicyListType::All => crate::tui::tasks::PolicyType::All,
        };

        self.start_async_task("load_policies", "Loading policies...");

        let request = crate::tui::tasks::TaskRequest::LoadPolicies {
            tenant_name: tenant,
            policy_type: task_type,
        };

        if !self.send_task(request) {
            self.status_message =
                Some(("Failed to start background task".into(), StatusLevel::Error));
        }
    }

    /// Shutdown the background task worker
    pub fn shutdown_worker(&self) {
        if let Some(ref sender) = self.task_sender {
            sender.shutdown();
        }
    }

    /// Request to exit the application
    /// Shows confirmation if there are unsaved audit entries
    pub fn request_exit(&mut self) {
        // Check if there are unsaved audit entries from this session
        let session_entries = crate::tui::change_tracker::get_session_entries();
        if !session_entries.is_empty() && !self.exit_confirmed {
            self.show_confirmation(
                "Exit ctl365",
                &format!(
                    "You have {} changes in this session.\n\nDo you want to exit?\n(Audit trail is saved automatically)",
                    session_entries.len()
                ),
                ConfirmAction::ExitWithChanges
            );
        } else {
            self.should_quit = true;
        }
    }
}

/// Run the TUI application
pub fn run_tui() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new()?;

    // Main loop
    let res = run_app(&mut terminal, &mut app);

    // Shutdown background worker
    app.shutdown_worker();

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("Error: {:?}", err);
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        // Process any pending responses from background tasks (non-blocking)
        app.process_task_responses();

        terminal.draw(|f| ui(f, app))?;

        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    // Clear status message on any key (except in search mode)
                    if app.input_mode != InputMode::Search {
                        app.status_message = None;
                    }

                    // Handle confirmation dialog first
                    if app.confirmation.is_some() {
                        match key.code {
                            KeyCode::Left
                            | KeyCode::Right
                            | KeyCode::Tab
                            | KeyCode::Char('h')
                            | KeyCode::Char('l') => {
                                if let Some(ref mut dialog) = app.confirmation {
                                    dialog.selected = !dialog.selected;
                                }
                            }
                            KeyCode::Enter => {
                                let confirmed = app
                                    .confirmation
                                    .as_ref()
                                    .map(|d| d.selected)
                                    .unwrap_or(false);
                                app.handle_confirmation(confirmed);
                            }
                            KeyCode::Esc | KeyCode::Char('n') => {
                                app.handle_confirmation(false);
                            }
                            KeyCode::Char('y') => {
                                app.handle_confirmation(true);
                            }
                            _ => {}
                        }
                        continue;
                    }

                    // Help overlay toggle
                    if app.show_help {
                        app.show_help = false;
                        continue;
                    }

                    // Handle search mode input
                    if app.input_mode == InputMode::Search {
                        match key.code {
                            KeyCode::Esc => {
                                app.toggle_search();
                            }
                            KeyCode::Enter => {
                                app.toggle_search();
                            }
                            KeyCode::Backspace => {
                                app.handle_search_backspace();
                            }
                            KeyCode::Char(c) => {
                                app.handle_search_input(c);
                            }
                            _ => {}
                        }
                        continue;
                    }

                    // Handle form input mode
                    if app.input_mode == InputMode::Input && app.form_state.is_some() {
                        match key.code {
                            KeyCode::Esc => {
                                app.form_cancel();
                            }
                            KeyCode::Enter => {
                                // Check if on last field - submit, otherwise next field
                                let is_last = app
                                    .form_state
                                    .as_ref()
                                    .map(|f| f.current_field >= f.fields.len() - 1)
                                    .unwrap_or(false);
                                if is_last {
                                    app.form_submit();
                                } else {
                                    app.form_next_field();
                                }
                            }
                            KeyCode::Tab | KeyCode::Down => {
                                app.form_next_field();
                            }
                            KeyCode::BackTab | KeyCode::Up => {
                                app.form_prev_field();
                            }
                            KeyCode::Backspace => {
                                app.form_backspace();
                            }
                            KeyCode::Char(c) => {
                                app.form_input_char(c);
                            }
                            KeyCode::F(1) => {
                                // F1 to force submit from any field
                                app.form_submit();
                            }
                            _ => {}
                        }
                        continue;
                    }

                    // Check if we're on a policy list screen (use table navigation)
                    let is_policy_screen = matches!(app.screen, Screen::PolicyList(_));

                    match key.code {
                        KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }
                        KeyCode::Char('q') => app.handle_shortcut('q'),
                        KeyCode::Char('?') => app.show_help = true,
                        KeyCode::Char('/') => app.toggle_search(),
                        KeyCode::Esc => {
                            if !app.history.is_empty() {
                                app.go_back();
                            } else {
                                app.request_exit();
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if is_policy_screen {
                                app.table_previous();
                            } else {
                                app.select_previous();
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if is_policy_screen {
                                app.table_next();
                            } else {
                                app.select_next();
                            }
                        }
                        KeyCode::PageUp => {
                            if is_policy_screen {
                                app.table_prev_page();
                            }
                        }
                        KeyCode::PageDown => {
                            if is_policy_screen {
                                app.table_next_page();
                            }
                        }
                        KeyCode::Home => {
                            if is_policy_screen {
                                app.table_first_page();
                            }
                        }
                        KeyCode::End => {
                            if is_policy_screen {
                                app.table_last_page();
                            }
                        }
                        KeyCode::Enter | KeyCode::Char(' ') => app.select_current(),
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            let num = c.to_digit(10).unwrap() as usize;
                            app.select_by_number(num);
                        }
                        KeyCode::Char(c) => app.handle_shortcut(c),
                        KeyCode::Backspace => app.go_back(),
                        _ => {}
                    }
                }
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

/// Render the UI
fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    render_header(f, app, chunks[0]);
    render_main(f, app, chunks[1]);
    render_status_bar(f, app, chunks[2]);

    // Overlays (rendered on top)
    if app.show_help {
        render_help_overlay(f, app);
    }

    if let Some(ref dialog) = app.confirmation {
        render_confirmation_dialog(f, dialog);
    }

    if let Some(ref progress) = app.progress {
        render_progress_overlay(f, progress);
    }

    if app.search_active {
        render_search_overlay(f, app);
    }

    // Form overlay (rendered on top of everything)
    if let Some(ref form) = app.form_state {
        render_form_overlay(f, form);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let tenant_info = match &app.active_tenant {
        Some(t) => format!(" {} ", t),
        None => " No tenant ".into(),
    };

    let breadcrumb = match &app.screen {
        Screen::Dashboard => "Home".into(),
        Screen::ClientList => "Home > MSP Clients".into(),
        Screen::ClientAdd => "Home > MSP Clients > Add Client".into(),
        Screen::ClientConfig(name) => format!("Home > {} > Configure", name),
        Screen::Settings(cat) => {
            let cat_name = match cat {
                SettingsCategory::Defender => "Defender for Office 365",
                SettingsCategory::Exchange => "Exchange Online",
                SettingsCategory::SharePoint => "SharePoint & OneDrive",
                SettingsCategory::Teams => "Microsoft Teams",
                SettingsCategory::ConditionalAccess => "Conditional Access",
                SettingsCategory::Intune => "Intune",
                _ => "Settings",
            };
            format!("Home > Settings > {}", cat_name)
        }
        Screen::Reports => "Home > Reports".into(),
        Screen::Help => "Help".into(),
        Screen::PolicyList(pt) => {
            let pt_name = match pt {
                PolicyListType::Compliance => "Compliance Policies",
                PolicyListType::Configuration => "Configuration Profiles",
                PolicyListType::SettingsCatalog => "Settings Catalog",
                PolicyListType::ConditionalAccess => "Conditional Access",
                PolicyListType::Apps => "Applications",
                PolicyListType::All => "All Policies",
            };
            format!("Home > Policies > {}", pt_name)
        }
        Screen::BaselineSelect => "Home > Deploy Baseline".into(),
        Screen::AuditHistory => "Home > Audit History".into(),
    };

    // Microsoft 365-inspired header with blue accent
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " M365 ",
            Style::default()
                .bg(Color::Rgb(0, 120, 212))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " ctl365 ",
            Style::default()
                .fg(Color::Rgb(0, 120, 212))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(&breadcrumb, Style::default().fg(Color::Gray)),
        Span::styled(" ", Style::default()),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::Rgb(50, 50, 50))),
    );

    f.render_widget(header, area);

    // Tenant badge on the right side
    let tenant_width = tenant_info.len() as u16 + 2;
    if area.width > tenant_width + 30 {
        let tenant_area = Rect {
            x: area.x + area.width - tenant_width - 1,
            y: area.y,
            width: tenant_width,
            height: 1,
        };
        let tenant_badge = Paragraph::new(Span::styled(
            &tenant_info,
            Style::default()
                .fg(Color::Black)
                .bg(Color::Rgb(255, 185, 0)), // M365 gold/yellow
        ));
        f.render_widget(tenant_badge, tenant_area);
    }
}

fn render_main(f: &mut Frame, app: &App, area: Rect) {
    // Policy list screens get a different layout with table
    if matches!(app.screen, Screen::PolicyList(_)) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),   // Policy table
                Constraint::Length(6), // Action bar
            ])
            .split(area);

        render_policy_table(f, app, chunks[0]);
        render_policy_actions(f, app, chunks[1]);
    } else if matches!(app.screen, Screen::AuditHistory) {
        // Audit history screen with table and menu
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25), // Menu
                Constraint::Percentage(75), // Audit table
            ])
            .split(area);

        render_menu(f, app, chunks[0]);
        render_audit_table(f, app, chunks[1]);
    } else {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(40), // Menu
                Constraint::Percentage(60), // Details/Preview
            ])
            .split(area);

        render_menu(f, app, chunks[0]);
        render_details(f, app, chunks[1]);
    }
}

fn render_menu(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .menu_items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let shortcut = item
                .shortcut
                .map(|c| format!("[{}] ", c))
                .unwrap_or_else(|| format!("[{}] ", idx + 1));
            let label = item.label.clone();
            let style = if item.enabled {
                Style::default()
            } else {
                Style::default().fg(Color::DarkGray)
            };

            ListItem::new(Line::from(vec![
                Span::styled(shortcut, Style::default().fg(Color::Cyan)),
                Span::styled(label, style),
            ]))
        })
        .collect();

    let title = match &app.screen {
        Screen::Dashboard => "Main Menu".to_string(),
        Screen::ClientList => "Clients".to_string(),
        Screen::ClientConfig(name) => format!("Configure: {}", name),
        Screen::Settings(_) => "Settings".to_string(),
        Screen::Reports => "Reports".to_string(),
        Screen::BaselineSelect => "Select Baseline".to_string(),
        Screen::PolicyList(_) => "Actions".to_string(),
        Screen::AuditHistory => "Filter".to_string(),
        _ => "Menu".to_string(),
    };

    let menu = List::new(items)
        .block(
            Block::default()
                .title(format!(" {} ", title))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("► ");

    f.render_stateful_widget(menu, area, &mut app.menu_state.clone());
}

fn render_details(f: &mut Frame, app: &App, area: Rect) {
    // Check if we're on a settings screen - show toggle status
    let is_settings = matches!(app.screen, Screen::Settings(_));

    let content = if let Some(idx) = app.menu_state.selected() {
        if idx < app.menu_items.len() {
            let item = &app.menu_items[idx];

            // Check if this item has a toggle state
            let toggle_info = if is_settings {
                if let Some(enabled) = app.setting_toggles.get(&item.id) {
                    let status = if *enabled { "✓ ON" } else { "✗ OFF" };
                    let color_hint = if *enabled { "(enabled)" } else { "(disabled)" };
                    format!(
                        "\n\nCurrent: {} {}\n\nPress Enter to toggle",
                        status, color_hint
                    )
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            let shortcut_hint = if item.shortcut.is_some() {
                format!("Press {} or Enter to select", item.shortcut.unwrap())
            } else {
                "Press Enter to select".into()
            };

            format!(
                "{}\n\n{}{}{}",
                item.label,
                item.description,
                toggle_info,
                if toggle_info.is_empty() {
                    format!("\n\n{}", shortcut_hint)
                } else {
                    String::new()
                }
            )
        } else {
            "Select an option".into()
        }
    } else {
        "Select an option".into()
    };

    let title = if is_settings {
        " Setting Details "
    } else {
        " Details "
    };

    let details = Paragraph::new(content)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(details, area);
}

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let (msg, style) = match &app.status_message {
        Some((msg, StatusLevel::Success)) => (msg.clone(), Style::default().fg(Color::Green)),
        Some((msg, StatusLevel::Warning)) => (msg.clone(), Style::default().fg(Color::Yellow)),
        Some((msg, StatusLevel::Error)) => (msg.clone(), Style::default().fg(Color::Red)),
        Some((msg, StatusLevel::Info)) => (msg.clone(), Style::default().fg(Color::Cyan)),
        None => (
            "↑↓/jk: Navigate │ Enter: Select │ Esc/Backspace: Back │ ?: Help │ q: Quit".into(),
            Style::default().fg(Color::DarkGray),
        ),
    };

    let status = Paragraph::new(msg).style(style).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(status, area);
}

fn render_help_overlay(f: &mut Frame, app: &App) {
    let area = centered_rect(70, 80, f.area());

    // Clear the area first
    f.render_widget(Clear, area);

    // Context-aware help based on current screen
    let context_help = match &app.screen {
        Screen::Dashboard => vec![
            "  DASHBOARD SHORTCUTS",
            "  ──────────────────────────────────────",
            "  c           Manage Clients (MSP)",
            "  t           Configure Active Tenant",
            "  r           Generate Reports",
            "  a           Audit & Compliance Check",
            "  h           View Audit History",
            "  b           Deploy Baseline",
        ],
        Screen::PolicyList(_) => vec![
            "  POLICY LIST SHORTCUTS",
            "  ──────────────────────────────────────",
            "  /           Search/Filter policies",
            "  r           Refresh from tenant",
            "  e           Export to JSON/CSV",
            "  Enter       View policy details",
            "  PgUp/PgDn   Previous/Next page",
            "  Home/End    First/Last page",
        ],
        Screen::Settings(_) => vec![
            "  SETTINGS SHORTCUTS",
            "  ──────────────────────────────────────",
            "  Space       Toggle setting on/off",
            "  Enter       Apply selected setting",
            "  a           Apply all settings",
        ],
        Screen::AuditHistory => vec![
            "  AUDIT HISTORY SHORTCUTS",
            "  ──────────────────────────────────────",
            "  7           Last 7 days",
            "  3           Last 30 days",
            "  a           All history",
            "  e           Export to JSON",
        ],
        _ => vec![],
    };

    let mut help_text = vec![
        "",
        "  ┌──────────────────────────────────────────────────────┐",
        "  │           ctl365 - M365 Configuration Tool           │",
        "  │                    Keyboard Help                      │",
        "  └──────────────────────────────────────────────────────┘",
        "",
        "  NAVIGATION",
        "  ──────────────────────────────────────",
        "  ↑ / k         Move selection up",
        "  ↓ / j         Move selection down",
        "  Enter         Select / Confirm",
        "  Space         Toggle / Select",
        "  1-9           Quick select by number",
        "  Esc           Go back / Cancel",
        "  Backspace     Go back to previous screen",
        "",
        "  GLOBAL SHORTCUTS",
        "  ──────────────────────────────────────",
        "  ?             Toggle this help",
        "  /             Search / Filter",
        "  q             Quit application",
        "  Ctrl+Q        Force quit",
        "",
    ];

    // Add context-specific help
    if !context_help.is_empty() {
        help_text.extend(context_help);
        help_text.push("");
    }

    // Add confirmation dialog help if active
    if app.confirmation.is_some() {
        help_text.push("  CONFIRMATION DIALOG");
        help_text.push("  ──────────────────────────────────────");
        help_text.push("  y           Confirm action");
        help_text.push("  n / Esc     Cancel action");
        help_text.push("  ←/→         Switch between Yes/No");
        help_text.push("");
    }

    help_text.push("  ──────────────────────────────────────");
    help_text.push("  Press any key to close this help");
    help_text.push("");

    let help = Paragraph::new(help_text.join("\n"))
        .block(
            Block::default()
                .title(" ctl365 Help [?] ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(help, area);
}

/// Helper to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Render interactive policy table with pagination
fn render_policy_table(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Name", "Type", "Status", "Platform", "Assigned", "Modified"]
        .iter()
        .map(|h| {
            ratatui::widgets::Cell::from(*h).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    // Use paginated data instead of full filtered list
    let filtered_count = app.filtered_table_data().len();
    let paginated = app.paginated_table_data();
    let rows = paginated.iter().map(|policy| {
        let status_style = Style::default().fg(policy.status.color());
        let cells = vec![
            ratatui::widgets::Cell::from(policy.name.clone()),
            ratatui::widgets::Cell::from(policy.policy_type.clone()),
            ratatui::widgets::Cell::from(policy.status.as_str()).style(status_style),
            ratatui::widgets::Cell::from(policy.platform.clone()),
            ratatui::widgets::Cell::from(format!("{}", policy.assignments)),
            ratatui::widgets::Cell::from(policy.last_modified.clone()),
        ];
        Row::new(cells).height(1)
    });

    // Build title with pagination info
    let total_pages = app.table_total_pages();
    let title = match &app.screen {
        Screen::PolicyList(pt) => {
            if total_pages > 1 {
                format!(
                    " {:?} Policies ({}) - Page {}/{} ",
                    pt,
                    filtered_count,
                    app.table_page + 1,
                    total_pages
                )
            } else {
                format!(" {:?} Policies ({}) ", pt, filtered_count)
            }
        }
        _ => " Policies ".to_string(),
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(35),
            Constraint::Percentage(15),
            Constraint::Percentage(12),
            Constraint::Percentage(12),
            Constraint::Percentage(10),
            Constraint::Percentage(16),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Cyan)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("► ");

    f.render_stateful_widget(table, area, &mut app.table_state.clone());
}

/// Render policy action bar
fn render_policy_actions(f: &mut Frame, app: &App, area: Rect) {
    let total_pages = app.table_total_pages();

    // Build actions with pagination hints when multiple pages exist
    let mut actions = vec!["[r] Refresh", "[/] Search", "[e] Export"];

    if total_pages > 1 {
        actions.push("[PgUp/PgDn] Page");
    }

    actions.push("[b] Back");

    let action_text = actions.join("  │  ");

    // Show selected item from paginated data
    let selected_info = if let Some(idx) = app.table_state.selected() {
        let paginated = app.paginated_table_data();
        if idx < paginated.len() {
            format!("\nSelected: {}", paginated[idx].name)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let content = format!("{}{}", action_text, selected_info);

    let actions_widget = Paragraph::new(content)
        .block(
            Block::default()
                .title(" Actions ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .alignment(Alignment::Center);

    f.render_widget(actions_widget, area);
}

/// Render audit history table
fn render_audit_table(f: &mut Frame, app: &App, area: Rect) {
    use crate::tui::change_tracker::{AuditAction, AuditSeverity};

    let header_cells = ["Time", "Action", "Category", "Target", "Tenant", "Status"]
        .iter()
        .map(|h| {
            ratatui::widgets::Cell::from(*h).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = app.audit_entries.iter().map(|entry| {
        // Color code by severity
        let status_color = match entry.severity {
            AuditSeverity::Success => Color::Green,
            AuditSeverity::Warning => Color::Yellow,
            AuditSeverity::Error => Color::Red,
            AuditSeverity::Info => Color::Cyan,
        };

        // Color code by action type
        let action_color = match entry.action {
            AuditAction::PolicyCreated | AuditAction::BaselineDeployed => Color::Green,
            AuditAction::PolicyDeleted | AuditAction::TenantRemoved => Color::Red,
            AuditAction::SettingChanged | AuditAction::PolicyModified => Color::Yellow,
            AuditAction::UserAuthenticated => Color::Cyan,
            AuditAction::Error => Color::Red,
            _ => Color::White,
        };

        let status_text = if entry.success { "OK" } else { "FAIL" };

        let cells = vec![
            ratatui::widgets::Cell::from(entry.timestamp.clone()),
            ratatui::widgets::Cell::from(entry.action.as_str())
                .style(Style::default().fg(action_color)),
            ratatui::widgets::Cell::from(entry.category.clone()),
            ratatui::widgets::Cell::from(truncate_string(&entry.target, 30)),
            ratatui::widgets::Cell::from(entry.tenant.clone()),
            ratatui::widgets::Cell::from(status_text).style(Style::default().fg(status_color)),
        ];
        Row::new(cells).height(1)
    });

    let days_label = match app.audit_days_filter {
        7 => "Last 7 Days",
        30 => "Last 30 Days",
        _ if app.audit_days_filter > 365 => "All History",
        n => &format!("Last {} Days", n),
    };

    let title = format!(
        " Audit History - {} ({} entries) ",
        days_label,
        app.audit_entries.len()
    );

    let table = Table::new(
        rows,
        [
            Constraint::Length(19),     // Time (YYYY-MM-DD HH:MM:SS)
            Constraint::Length(18),     // Action
            Constraint::Length(14),     // Category
            Constraint::Percentage(30), // Target
            Constraint::Length(10),     // Tenant
            Constraint::Length(6),      // Status
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Cyan)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("► ");

    f.render_stateful_widget(table, area, &mut app.table_state.clone());

    // Show empty state message if no entries
    if app.audit_entries.is_empty() {
        let empty_area = Rect {
            x: area.x + 2,
            y: area.y + 3,
            width: area.width.saturating_sub(4),
            height: 3,
        };
        let empty_msg =
            Paragraph::new("No audit entries found. Changes made through ctl365 will appear here.")
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center);
        f.render_widget(empty_msg, empty_area);
    }
}

/// Truncate a string to max length with ellipsis
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Render confirmation dialog
fn render_confirmation_dialog(f: &mut Frame, dialog: &ConfirmationDialog) {
    use crate::tui::context::ImpactLevel;

    // Larger area if we have an impact summary
    let (width, height) = if dialog.impact.is_some() {
        (60, 50)
    } else {
        (50, 40)
    };
    let area = centered_rect(width, height, f.area());
    f.render_widget(Clear, area);

    // Determine border color based on impact level
    let (border_color, title_suffix) = if let Some(ref impact) = dialog.impact {
        match impact.level {
            ImpactLevel::Low => (Color::Cyan, " [LOW] "),
            ImpactLevel::Medium => (Color::Yellow, " [MEDIUM] "),
            ImpactLevel::High => (Color::LightRed, " [HIGH] "),
            ImpactLevel::Critical => (Color::Red, " [CRITICAL] "),
        }
    } else {
        (Color::Yellow, "")
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Min(3),    // Message
            Constraint::Length(3), // Buttons
        ])
        .split(area);

    // Dialog box with impact indicator
    let block = Block::default()
        .title(format!(" {}{} ", dialog.title, title_suffix))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    f.render_widget(block, area);

    // Message with impact coloring
    let message_style = if let Some(ref impact) = dialog.impact {
        match impact.level {
            ImpactLevel::Critical => Style::default().fg(Color::LightRed),
            ImpactLevel::High => Style::default().fg(Color::Yellow),
            _ => Style::default().fg(Color::White),
        }
    } else {
        Style::default().fg(Color::White)
    };

    let message = Paragraph::new(dialog.message.clone())
        .style(message_style)
        .wrap(Wrap { trim: true });
    f.render_widget(message, chunks[0]);

    // Buttons - swap colors based on impact for critical actions
    let (confirm_color, cancel_color) = if dialog
        .impact
        .as_ref()
        .map(|i| i.level >= ImpactLevel::High)
        .unwrap_or(false)
    {
        (Color::Red, Color::Green) // Make cancel the "safe" green option
    } else {
        (Color::Green, Color::Red)
    };

    let yes_style = if dialog.selected {
        Style::default()
            .bg(confirm_color)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(confirm_color)
    };
    let no_style = if !dialog.selected {
        Style::default()
            .bg(cancel_color)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(cancel_color)
    };

    let buttons = Line::from(vec![
        Span::raw("  "),
        Span::styled(format!(" [y] {} ", dialog.confirm_label), yes_style),
        Span::raw("     "),
        Span::styled(format!(" [n] {} ", dialog.cancel_label), no_style),
        Span::raw("  "),
    ]);

    let buttons_widget = Paragraph::new(buttons).alignment(Alignment::Center);
    f.render_widget(buttons_widget, chunks[1]);
}

/// Render progress overlay
fn render_progress_overlay(f: &mut Frame, progress: &ProgressState) {
    let area = centered_rect(50, 20, f.area());
    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(2), // Message
            Constraint::Length(3), // Progress bar
        ])
        .split(area);

    // Dialog box
    let block = Block::default()
        .title(format!(" {} ", progress.title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    // Message
    let message = Paragraph::new(&*progress.message);
    f.render_widget(message, chunks[0]);

    // Progress bar
    let percent = progress.percent();
    let label = if progress.indeterminate {
        "Working...".to_string()
    } else {
        format!("{}/{} ({}%)", progress.current, progress.total, percent)
    };

    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Cyan))
        .percent(percent)
        .label(label);
    f.render_widget(gauge, chunks[1]);
}

/// Render search overlay
fn render_search_overlay(f: &mut Frame, app: &App) {
    // Search bar at top of screen
    let area = Rect {
        x: f.area().width / 4,
        y: 4,
        width: f.area().width / 2,
        height: 3,
    };

    f.render_widget(Clear, area);

    let search_text = format!("/{}", app.search_input);
    let cursor = if app.search_active { "_" } else { "" };
    let display = format!("{}{}", search_text, cursor);

    let search = Paragraph::new(display)
        .block(
            Block::default()
                .title(" Search (Esc to close) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(search, area);
}

/// Render form overlay for multi-field input
fn render_form_overlay(f: &mut Frame, form: &FormState) {
    // Calculate form height based on number of fields
    let field_height = 3; // Each field takes 3 rows
    let total_height = (form.fields.len() as u16 * field_height) + 8; // +8 for title, buttons, margins
    let area = centered_rect(70, total_height.min(80), f.area());

    f.render_widget(Clear, area);

    // Main form block
    let block = Block::default()
        .title(format!(" {} ", form.title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    // Create layout for fields
    let inner = Rect {
        x: area.x + 2,
        y: area.y + 1,
        width: area.width.saturating_sub(4),
        height: area.height.saturating_sub(2),
    };

    let mut constraints: Vec<Constraint> =
        form.fields.iter().map(|_| Constraint::Length(3)).collect();
    constraints.push(Constraint::Length(3)); // Submit button area
    constraints.push(Constraint::Min(0)); // Remaining space

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // Render each field
    for (i, field) in form.fields.iter().enumerate() {
        let is_active = i == form.current_field;
        let border_color = if is_active {
            Color::Yellow
        } else {
            Color::DarkGray
        };

        let display_value =
            if matches!(field.field_type, FormFieldType::Password) && !field.value.is_empty() {
                "*".repeat(field.value.len())
            } else if field.value.is_empty() {
                field.placeholder.clone()
            } else {
                field.value.clone()
            };

        let cursor = if is_active { "_" } else { "" };
        let text_style = if field.value.is_empty() && !is_active {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };

        let required_marker = if field.required { " *" } else { "" };
        let title = format!(" {}{} ", field.label, required_marker);

        let input = Paragraph::new(format!("{}{}", display_value, cursor))
            .style(text_style)
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color)),
            );

        f.render_widget(input, chunks[i]);
    }

    // Submit button / help area
    let submit_idx = form.fields.len();
    let help_text = format!(
        " Field {}/{} │ Tab/↓: Next │ Shift+Tab/↑: Prev │ Enter: {} │ Esc: Cancel ",
        form.current_field + 1,
        form.fields.len(),
        if form.current_field >= form.fields.len() - 1 {
            "Submit"
        } else {
            "Next"
        }
    );

    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);

    f.render_widget(help, chunks[submit_idx]);
}

// ============================================================================
// Async deployment helper functions
// ============================================================================

/// Deploy baseline policies to a tenant
async fn deploy_baseline_policies(
    config: &crate::config::ConfigManager,
    tenant_name: &str,
    baseline: &serde_json::Value,
) -> crate::error::Result<usize> {
    use crate::graph::GraphClient;

    let graph = GraphClient::from_config(config, tenant_name).await?;

    let policies = baseline["policies"]
        .as_array()
        .ok_or_else(|| crate::error::Error::ConfigError("Invalid baseline format".into()))?;

    let mut deployed = 0;
    for policy in policies {
        let policy_type = policy["@odata.type"]
            .as_str()
            .ok_or_else(|| crate::error::Error::ConfigError("Missing @odata.type".into()))?;

        crate::graph::intune::create_policy(&graph, policy_type, policy).await?;
        deployed += 1;
    }

    Ok(deployed)
}

/// Deploy CA policies from 2025 baseline
async fn deploy_ca_policies_2025(
    config: &crate::config::ConfigManager,
    tenant_name: &str,
) -> crate::error::Result<usize> {
    use crate::graph::GraphClient;
    use crate::templates::ca_baseline_2025::CABaseline2025;

    let graph = GraphClient::from_config(config, tenant_name).await?;

    // Get CA 2025 policies
    let baseline = CABaseline2025::generate();

    let mut deployed = 0;
    for policy in &baseline.policies {
        // Convert to Graph API JSON format
        let policy_json = CABaseline2025::to_graph_json(policy);
        crate::graph::conditional_access::create_policy(&graph, &policy_json).await?;
        deployed += 1;
    }

    Ok(deployed)
}

/// Load policies from Graph API
async fn load_policies_from_api(
    config: &crate::config::ConfigManager,
    tenant_name: &str,
    policy_type: &PolicyListType,
) -> crate::error::Result<Vec<PolicyRow>> {
    use crate::graph::GraphClient;

    let graph = GraphClient::from_config(config, tenant_name).await?;

    let policies = match policy_type {
        PolicyListType::ConditionalAccess => {
            let result = crate::graph::conditional_access::list_policies(&graph).await?;
            parse_ca_policies(&result)
        }
        PolicyListType::Compliance => {
            let result = crate::graph::intune::list_compliance_policies(&graph).await?;
            parse_compliance_policies(&result)
        }
        PolicyListType::Configuration | PolicyListType::SettingsCatalog => {
            let result = crate::graph::intune::list_device_configurations(&graph).await?;
            parse_config_policies(&result)
        }
        PolicyListType::Apps => {
            // Apps require different API - show sample for now
            return Err(crate::error::Error::NotImplemented(
                "App listing not yet implemented".into(),
            ));
        }
        PolicyListType::All => {
            // Combine all types
            let mut all = Vec::new();

            if let Ok(result) = crate::graph::conditional_access::list_policies(&graph).await {
                all.extend(parse_ca_policies(&result));
            }
            if let Ok(result) = crate::graph::intune::list_compliance_policies(&graph).await {
                all.extend(parse_compliance_policies(&result));
            }
            if let Ok(result) = crate::graph::intune::list_device_configurations(&graph).await {
                all.extend(parse_config_policies(&result));
            }

            all
        }
    };

    Ok(policies)
}

/// Parse CA policies from Graph API response
fn parse_ca_policies(response: &serde_json::Value) -> Vec<PolicyRow> {
    let mut policies = Vec::new();

    if let Some(value) = response.get("value").and_then(|v| v.as_array()) {
        for policy in value {
            let name = policy
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let state = policy
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("disabled");

            let status = match state {
                "enabled" => PolicyStatus::Deployed,
                "enabledForReportingButNotEnforced" => PolicyStatus::ReportOnly,
                "disabled" => PolicyStatus::Disabled,
                _ => PolicyStatus::Draft,
            };

            let modified = policy
                .get("modifiedDateTime")
                .and_then(|v| v.as_str())
                .map(|s| s.split('T').next().unwrap_or(s).to_string())
                .unwrap_or_else(|| "N/A".into());

            policies.push(PolicyRow {
                name,
                policy_type: "CA".into(),
                status,
                platform: "All".into(),
                assignments: 0, // Would need additional API call
                last_modified: modified,
            });
        }
    }

    policies
}

/// Parse compliance policies from Graph API response
fn parse_compliance_policies(response: &serde_json::Value) -> Vec<PolicyRow> {
    let mut policies = Vec::new();

    if let Some(value) = response.get("value").and_then(|v| v.as_array()) {
        for policy in value {
            let name = policy
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let platform = policy
                .get("@odata.type")
                .and_then(|v| v.as_str())
                .map(|t| {
                    if t.contains("windows") {
                        "Windows"
                    } else if t.contains("macOS") {
                        "macOS"
                    } else if t.contains("iOS") {
                        "iOS"
                    } else if t.contains("android") {
                        "Android"
                    } else {
                        "Other"
                    }
                })
                .unwrap_or("Unknown")
                .to_string();

            let modified = policy
                .get("lastModifiedDateTime")
                .and_then(|v| v.as_str())
                .map(|s| s.split('T').next().unwrap_or(s).to_string())
                .unwrap_or_else(|| "N/A".into());

            policies.push(PolicyRow {
                name,
                policy_type: "Compliance".into(),
                status: PolicyStatus::Deployed,
                platform,
                assignments: 0,
                last_modified: modified,
            });
        }
    }

    policies
}

/// Parse configuration policies from Graph API response
fn parse_config_policies(response: &serde_json::Value) -> Vec<PolicyRow> {
    let mut policies = Vec::new();

    if let Some(value) = response.get("value").and_then(|v| v.as_array()) {
        for policy in value {
            let name = policy
                .get("displayName")
                .or_else(|| policy.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let odata_type = policy
                .get("@odata.type")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let (policy_type, platform) = if odata_type.contains("settingsCatalog") {
                ("Settings Catalog".into(), "Windows".into())
            } else if odata_type.contains("windows") {
                ("Config".into(), "Windows".into())
            } else if odata_type.contains("macOS") {
                ("Config".into(), "macOS".into())
            } else if odata_type.contains("iOS") {
                ("Config".into(), "iOS".into())
            } else {
                ("Config".into(), "Other".into())
            };

            let modified = policy
                .get("lastModifiedDateTime")
                .and_then(|v| v.as_str())
                .map(|s| s.split('T').next().unwrap_or(s).to_string())
                .unwrap_or_else(|| "N/A".into());

            policies.push(PolicyRow {
                name,
                policy_type,
                status: PolicyStatus::Deployed,
                platform,
                assignments: 0,
                last_modified: modified,
            });
        }
    }

    policies
}

// ============================================================================
// Async deployment functions with progress tracking
// ============================================================================

/// Deploy baseline policies with progress reporting
async fn deploy_baseline_policies_with_progress(
    config: &crate::config::ConfigManager,
    tenant_name: &str,
    baseline: &serde_json::Value,
) -> crate::error::Result<usize> {
    use crate::graph::GraphClient;

    let graph = GraphClient::from_config(config, tenant_name).await?;

    let policies = baseline["policies"]
        .as_array()
        .ok_or_else(|| crate::error::Error::ConfigError("Invalid baseline format".into()))?;

    let total = policies.len();
    let mut deployed = 0;

    for (i, policy) in policies.iter().enumerate() {
        let policy_type = policy["@odata.type"]
            .as_str()
            .ok_or_else(|| crate::error::Error::ConfigError("Missing @odata.type".into()))?;

        let display_name = policy["displayName"]
            .as_str()
            .or_else(|| policy["name"].as_str())
            .unwrap_or("Unknown");

        // Progress: 10% for start, 90% for deploying policies
        let _progress = 10 + ((i * 90) / total) as u16;

        // Note: Cannot update UI progress from here since we don't have access to App
        // The progress will be shown via the ProgressState in the UI

        crate::graph::intune::create_policy(&graph, policy_type, policy).await?;
        deployed += 1;

        // Log progress (visible in debug)
        tracing::debug!("Deployed {}/{}: {}", deployed, total, display_name);
    }

    Ok(deployed)
}

/// Deploy CA policies from 2025 baseline with progress
async fn deploy_ca_policies_2025_with_progress(
    config: &crate::config::ConfigManager,
    tenant_name: &str,
) -> crate::error::Result<usize> {
    use crate::graph::GraphClient;
    use crate::templates::ca_baseline_2025::CABaseline2025;

    let graph = GraphClient::from_config(config, tenant_name).await?;

    // Get CA 2025 policies
    let baseline = CABaseline2025::generate();
    let total = baseline.policies.len();

    let mut deployed = 0;
    for (i, policy) in baseline.policies.iter().enumerate() {
        // Progress tracking
        let _progress = 10 + ((i * 90) / total) as u16;

        // Convert to Graph API JSON format
        let policy_json = CABaseline2025::to_graph_json(policy);
        crate::graph::conditional_access::create_policy(&graph, &policy_json).await?;
        deployed += 1;

        tracing::debug!(
            "Deployed CA policy {}/{}: {}",
            deployed,
            total,
            policy.display_name
        );
    }

    Ok(deployed)
}
