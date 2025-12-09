#![recursion_limit = "256"]
// Allow dead code for API modules that are built for future use
#![allow(dead_code)]

mod cmd;
mod config;
mod error;
mod graph;
mod templates;
mod tui;

use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser, Debug)]
#[command(
    name = "ctl365",
    about = "Control, configure, and secure Microsoft 365 — at scale",
    version,
    long_about = "Enterprise-grade Microsoft 365 deployment automation CLI\n\n\
                  Automate Intune baselines, Defender, BitLocker, Conditional Access, and more.\n\
                  Built for MSPs and IT professionals managing multiple tenants."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Authenticate to Microsoft Graph API
    Login(cmd::login::LoginArgs),

    /// Logout and clear cached credentials
    Logout(cmd::login::LogoutArgs),

    /// Manage tenant configurations
    #[command(subcommand)]
    Tenant(TenantCommands),

    /// Manage baseline configurations
    #[command(subcommand)]
    Baseline(BaselineCommands),

    /// Manage Conditional Access policies
    #[command(subcommand)]
    Ca(CaCommands),

    /// Export/Import for MSP operations
    #[command(subcommand)]
    Export(ExportCommands),

    /// Audit compliance and detect drift
    #[command(subcommand)]
    Audit(AuditCommands),

    /// Deploy and manage applications
    #[command(subcommand)]
    App(AppCommands),

    /// Manage Windows Autopilot deployment
    #[command(subcommand)]
    Autopilot(AutopilotCommands),

    /// Package applications for Intune (Win32 Content Prep)
    #[command(subcommand)]
    Package(PackageCommands),

    /// Deploy and manage platform scripts
    #[command(subcommand)]
    Script(ScriptCommands),

    /// GPO to Intune migration tools
    #[command(subcommand)]
    Gpo(GpoCommands),

    /// CISA SCuBA baseline assessment
    #[command(subcommand)]
    Scuba(ScubaCommands),

    /// Azure AD Connect documentation and migration
    #[command(subcommand)]
    Aadconnect(AadconnectCommands),

    /// Manage SharePoint sites and pages
    #[command(subcommand)]
    Sharepoint(SharePointCommands),

    /// Manage Viva Engage communities and roles
    #[command(subcommand)]
    Viva(VivaCommands),

    /// Manage Copilot agents and search
    #[command(subcommand)]
    Copilot(CopilotCommands),

    /// Interactive tenant configuration TUI
    #[command(subcommand, name = "tui")]
    Tui(TuiCommands),
}

#[derive(Subcommand, Debug)]
enum ExportCommands {
    /// Export all policies from active tenant (enhanced with assignments)
    Export(cmd::export_enhanced::ExportArgs),

    /// Import policies to active tenant (with assignment migration)
    Import(cmd::export_enhanced::ImportArgs),

    /// Compare two tenants or exports
    Compare(cmd::export_enhanced::CompareArgs),
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// Audit tenant against baseline (enhanced with scoring)
    Check(cmd::audit_enhanced::AuditArgs),

    /// Detect configuration drift (with auto-fix)
    Drift(cmd::audit_enhanced::DriftArgs),

    /// Generate compliance report
    Report(cmd::audit_enhanced::ReportArgs),
}

#[derive(Subcommand, Debug)]
enum CaCommands {
    /// Deploy Conditional Access policies
    Deploy(cmd::ca::DeployArgs),

    /// List deployed CA policies
    List(cmd::ca::ListArgs),

    /// Enable a CA policy (report-only → enforced)
    #[command(hide = true)]
    Enable,
}

#[derive(Subcommand, Debug)]
enum TenantCommands {
    /// Add a new tenant configuration
    Add(cmd::tenant::TenantAddArgs),

    /// List all configured tenants
    List(cmd::tenant::TenantListArgs),

    /// Switch active tenant
    Switch(cmd::tenant::TenantSwitchArgs),

    /// Remove a tenant configuration
    Remove(cmd::tenant::TenantRemoveArgs),

    /// Configure tenant-wide settings (Exchange, SharePoint, Teams)
    Configure(cmd::tenant_baseline::ConfigureArgs),

    /// Show current tenant configuration
    #[command(name = "show")]
    ShowConfig,
}

#[derive(Subcommand, Debug)]
enum BaselineCommands {
    /// Generate a new baseline configuration
    New(cmd::baseline::NewArgs),

    /// Apply a baseline to the active tenant
    Apply(cmd::baseline::ApplyArgs),

    /// Export a baseline to a JSON file
    Export(cmd::baseline::ExportArgs),

    /// List available baseline templates
    List,
}

#[derive(Subcommand, Debug)]
enum AppCommands {
    /// Deploy an application to Intune
    Deploy(cmd::app_deployment::DeployArgs),

    /// Deploy Microsoft 365 Apps
    #[command(name = "deploy-m365")]
    DeployM365(cmd::app_deployment::DeployM365Args),

    /// List deployed applications
    List(cmd::app_deployment::ListArgs),

    /// Remove an application
    Remove(cmd::app_deployment::RemoveArgs),

    /// Package a Win32 app for deployment
    Package(cmd::app_deployment::PackageArgs),
}

#[derive(Subcommand, Debug)]
enum AutopilotCommands {
    /// Import devices into Autopilot
    Import(cmd::autopilot::ImportArgs),

    /// Create an Autopilot deployment profile
    Profile(cmd::autopilot::ProfileArgs),

    /// Assign a profile to devices
    Assign(cmd::autopilot::AssignArgs),

    /// List Autopilot devices
    List(cmd::autopilot::ListArgs),

    /// Show device status
    Status(cmd::autopilot::StatusArgs),

    /// Sync Autopilot devices with Intune
    Sync,

    /// Delete an Autopilot device
    Delete(cmd::autopilot::DeleteArgs),
}

#[derive(Subcommand, Debug)]
enum PackageCommands {
    /// Package an application as .intunewin
    Create(cmd::package::PackageArgs),

    /// Upload a packaged app to Intune
    Upload(cmd::package::UploadArgs),
}

#[derive(Subcommand, Debug)]
enum ScriptCommands {
    /// Deploy a platform script (PowerShell, shell)
    Deploy(cmd::script::DeployScriptArgs),

    /// Deploy a proactive remediation (detection + remediation)
    Remediation(cmd::script::DeployRemediationArgs),

    /// List deployed scripts
    List(cmd::script::ListScriptsArgs),
}

#[derive(Subcommand, Debug)]
enum GpoCommands {
    /// Analyze GPO backup for Intune compatibility
    Analyze(cmd::gpo::AnalyzeArgs),

    /// Convert GPO to Settings Catalog format
    Convert(cmd::gpo::ConvertArgs),

    /// Deploy converted GPO policy to Intune
    Deploy(cmd::gpo::DeployConvertedArgs),
}

#[derive(Subcommand, Debug)]
enum ScubaCommands {
    /// Run SCuBA baseline assessment
    Audit(cmd::scuba::RunAuditArgs),

    /// Check ScubaGear status
    Status(cmd::scuba::CheckStatusArgs),

    /// View or export SCuBA baselines
    Baselines(cmd::scuba::BaselineArgs),
}

#[derive(Subcommand, Debug)]
enum AadconnectCommands {
    /// Export AAD Connect configuration documentation
    Export(cmd::aadconnect::ExportConfigArgs),

    /// Check sync status
    Status(cmd::aadconnect::SyncStatusArgs),

    /// Assess migration readiness
    Migration(cmd::aadconnect::MigrationCheckArgs),

    /// Compare on-prem AD with Entra ID
    Compare(cmd::aadconnect::CompareArgs),
}

#[derive(Subcommand, Debug)]
enum SharePointCommands {
    /// Create a new SharePoint site
    #[command(name = "site-create")]
    SiteCreate(cmd::sharepoint::SiteCreateArgs),

    /// List SharePoint sites
    #[command(name = "site-list")]
    SiteList(cmd::sharepoint::SiteListArgs),

    /// Get details of a specific site
    #[command(name = "site-get")]
    SiteGet(cmd::sharepoint::SiteGetArgs),

    /// Delete a SharePoint site
    #[command(name = "site-delete")]
    SiteDelete(cmd::sharepoint::SiteDeleteArgs),

    /// Create a new page in a site
    #[command(name = "page-create")]
    PageCreate(cmd::sharepoint::PageCreateArgs),

    /// List pages in a site
    #[command(name = "page-list")]
    PageList(cmd::sharepoint::PageListArgs),

    /// Delete a page from a site
    #[command(name = "page-delete")]
    PageDelete(cmd::sharepoint::PageDeleteArgs),

    /// List hub sites
    #[command(name = "hub-list")]
    HubList(cmd::sharepoint::HubListArgs),

    /// Register a site as a hub site
    #[command(name = "hub-set")]
    HubSet(cmd::sharepoint::HubSetArgs),

    /// Join a site to a hub
    #[command(name = "hub-join")]
    HubJoin(cmd::sharepoint::HubJoinArgs),
}

#[derive(Subcommand, Debug)]
enum VivaCommands {
    /// Create a new Viva Engage community
    #[command(name = "community-create")]
    CommunityCreate(cmd::viva::CommunityCreateArgs),

    /// List Viva Engage communities
    #[command(name = "community-list")]
    CommunityList(cmd::viva::CommunityListArgs),

    /// Delete a Viva Engage community
    #[command(name = "community-delete")]
    CommunityDelete(cmd::viva::CommunityDeleteArgs),

    /// Add a member to a community
    #[command(name = "community-add-member")]
    CommunityAddMember(cmd::viva::CommunityMemberArgs),

    /// Remove a member from a community
    #[command(name = "community-remove-member")]
    CommunityRemoveMember(cmd::viva::CommunityMemberArgs),

    /// Assign a Viva Engage role to a user
    #[command(name = "role-assign")]
    RoleAssign(cmd::viva::RoleAssignArgs),

    /// List Viva Engage role assignments
    #[command(name = "role-list")]
    RoleList(cmd::viva::RoleListArgs),

    /// Revoke a Viva Engage role assignment
    #[command(name = "role-revoke")]
    RoleRevoke(cmd::viva::RoleRevokeArgs),

    /// Configure Viva Connections home site
    #[command(name = "connections-home")]
    ConnectionsHome(cmd::viva::ConnectionsHomeSiteArgs),
}

#[derive(Subcommand, Debug)]
enum CopilotCommands {
    /// List Copilot agents in the catalog
    #[command(name = "agents-list")]
    AgentsList(cmd::copilot::AgentsListArgs),

    /// Get details of a specific Copilot agent
    #[command(name = "agents-get")]
    AgentsGet(cmd::copilot::AgentsGetArgs),

    /// Search content using Copilot APIs
    Search(cmd::copilot::SearchArgs),

    /// Export Copilot interactions (for compliance)
    #[command(name = "interactions-export")]
    InteractionsExport(cmd::copilot::InteractionsExportArgs),

    /// Get meeting insights
    #[command(name = "meeting-insights")]
    MeetingInsights(cmd::copilot::MeetingInsightsArgs),
}

#[derive(Subcommand, Debug)]
enum TuiCommands {
    /// Launch full-screen TUI dashboard (recommended)
    #[command(name = "dashboard", alias = "d")]
    Dashboard,

    /// MSP Client Management (add clients, generate reports)
    #[command(name = "clients")]
    Clients,

    /// Launch interactive configuration menu (dialoguer-based)
    #[command(name = "configure")]
    Configure,

    /// Quick single-setting change
    #[command(name = "quick")]
    Quick,

    /// Configure Defender for Office 365 interactively
    #[command(name = "defender")]
    Defender,

    /// Configure Exchange Online interactively
    #[command(name = "exchange")]
    Exchange,

    /// Configure SharePoint/OneDrive interactively
    #[command(name = "sharepoint")]
    SharePoint,

    /// Configure Teams interactively
    #[command(name = "teams")]
    Teams,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}

async fn run() -> error::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("ctl365=debug")
            .init();
    }

    match cli.command {
        Commands::Login(args) => cmd::login::login(args).await?,
        Commands::Logout(args) => cmd::login::logout(args).await?,
        Commands::Tenant(tenant_cmd) => match tenant_cmd {
            TenantCommands::Add(args) => cmd::tenant::add(args).await?,
            TenantCommands::List(args) => cmd::tenant::list(args).await?,
            TenantCommands::Switch(args) => cmd::tenant::switch(args).await?,
            TenantCommands::Remove(args) => cmd::tenant::remove(args).await?,
            TenantCommands::Configure(args) => cmd::tenant_baseline::configure(args).await?,
            TenantCommands::ShowConfig => cmd::tenant_baseline::show_config().await?,
        },
        Commands::Baseline(baseline_cmd) => match baseline_cmd {
            BaselineCommands::New(args) => cmd::baseline::new(args).await?,
            BaselineCommands::Apply(args) => cmd::baseline::apply(args).await?,
            BaselineCommands::Export(args) => cmd::baseline::export(args).await?,
            BaselineCommands::List => cmd::baseline::list().await?,
        },
        Commands::Ca(ca_cmd) => match ca_cmd {
            CaCommands::Deploy(args) => cmd::ca::deploy(args).await?,
            CaCommands::List(args) => cmd::ca::list(args).await?,
            CaCommands::Enable => {
                println!("{} Feature coming soon!", "CA Enable".cyan().bold());
            }
        },
        Commands::Export(export_cmd) => match export_cmd {
            ExportCommands::Export(args) => cmd::export_enhanced::export_enhanced(args).await?,
            ExportCommands::Import(args) => cmd::export_enhanced::import_enhanced(args).await?,
            ExportCommands::Compare(args) => cmd::export_enhanced::compare(args).await?,
        },
        Commands::Audit(audit_cmd) => match audit_cmd {
            AuditCommands::Check(args) => cmd::audit_enhanced::audit_enhanced(args).await?,
            AuditCommands::Drift(args) => cmd::audit_enhanced::drift_enhanced(args).await?,
            AuditCommands::Report(args) => cmd::audit_enhanced::report(args).await?,
        },
        Commands::App(app_cmd) => match app_cmd {
            AppCommands::Deploy(args) => cmd::app_deployment::deploy(args).await?,
            AppCommands::DeployM365(args) => cmd::app_deployment::deploy_m365(args).await?,
            AppCommands::List(args) => cmd::app_deployment::list(args).await?,
            AppCommands::Remove(args) => cmd::app_deployment::remove(args).await?,
            AppCommands::Package(args) => cmd::app_deployment::package(args).await?,
        },
        Commands::Autopilot(autopilot_cmd) => match autopilot_cmd {
            AutopilotCommands::Import(args) => cmd::autopilot::import(args).await?,
            AutopilotCommands::Profile(args) => cmd::autopilot::profile(args).await?,
            AutopilotCommands::Assign(args) => cmd::autopilot::assign(args).await?,
            AutopilotCommands::List(args) => cmd::autopilot::list(args).await?,
            AutopilotCommands::Status(args) => cmd::autopilot::status(args).await?,
            AutopilotCommands::Sync => cmd::autopilot::sync().await?,
            AutopilotCommands::Delete(args) => cmd::autopilot::delete(args).await?,
        },
        Commands::Package(package_cmd) => match package_cmd {
            PackageCommands::Create(args) => cmd::package::package(args).await?,
            PackageCommands::Upload(args) => cmd::package::upload(args).await?,
        },
        Commands::Script(script_cmd) => match script_cmd {
            ScriptCommands::Deploy(args) => cmd::script::deploy_script(args).await?,
            ScriptCommands::Remediation(args) => cmd::script::deploy_remediation(args).await?,
            ScriptCommands::List(args) => cmd::script::list_scripts(args).await?,
        },
        Commands::Gpo(gpo_cmd) => match gpo_cmd {
            GpoCommands::Analyze(args) => cmd::gpo::analyze(args).await?,
            GpoCommands::Convert(args) => cmd::gpo::convert(args).await?,
            GpoCommands::Deploy(args) => cmd::gpo::deploy_converted(args).await?,
        },
        Commands::Scuba(scuba_cmd) => match scuba_cmd {
            ScubaCommands::Audit(args) => cmd::scuba::run_audit(args).await?,
            ScubaCommands::Status(args) => cmd::scuba::check_status(args).await?,
            ScubaCommands::Baselines(args) => cmd::scuba::baselines(args).await?,
        },
        Commands::Aadconnect(aad_cmd) => match aad_cmd {
            AadconnectCommands::Export(args) => cmd::aadconnect::export_config(args).await?,
            AadconnectCommands::Status(args) => cmd::aadconnect::sync_status(args).await?,
            AadconnectCommands::Migration(args) => cmd::aadconnect::migration_check(args).await?,
            AadconnectCommands::Compare(args) => cmd::aadconnect::compare(args).await?,
        },
        Commands::Sharepoint(sp_cmd) => match sp_cmd {
            SharePointCommands::SiteCreate(args) => cmd::sharepoint::site_create(args).await?,
            SharePointCommands::SiteList(args) => cmd::sharepoint::site_list(args).await?,
            SharePointCommands::SiteGet(args) => cmd::sharepoint::site_get(args).await?,
            SharePointCommands::SiteDelete(args) => cmd::sharepoint::site_delete(args).await?,
            SharePointCommands::PageCreate(args) => cmd::sharepoint::page_create(args).await?,
            SharePointCommands::PageList(args) => cmd::sharepoint::page_list(args).await?,
            SharePointCommands::PageDelete(args) => cmd::sharepoint::page_delete(args).await?,
            SharePointCommands::HubList(args) => cmd::sharepoint::hub_list(args).await?,
            SharePointCommands::HubSet(args) => cmd::sharepoint::hub_set(args).await?,
            SharePointCommands::HubJoin(args) => cmd::sharepoint::hub_join(args).await?,
        },
        Commands::Viva(viva_cmd) => match viva_cmd {
            VivaCommands::CommunityCreate(args) => cmd::viva::community_create(args).await?,
            VivaCommands::CommunityList(args) => cmd::viva::community_list(args).await?,
            VivaCommands::CommunityDelete(args) => cmd::viva::community_delete(args).await?,
            VivaCommands::CommunityAddMember(args) => cmd::viva::community_add_member(args).await?,
            VivaCommands::CommunityRemoveMember(args) => cmd::viva::community_remove_member(args).await?,
            VivaCommands::RoleAssign(args) => cmd::viva::role_assign(args).await?,
            VivaCommands::RoleList(args) => cmd::viva::role_list(args).await?,
            VivaCommands::RoleRevoke(args) => cmd::viva::role_revoke(args).await?,
            VivaCommands::ConnectionsHome(args) => cmd::viva::connections_home_site(args).await?,
        },
        Commands::Copilot(copilot_cmd) => match copilot_cmd {
            CopilotCommands::AgentsList(args) => cmd::copilot::agents_list(args).await?,
            CopilotCommands::AgentsGet(args) => cmd::copilot::agents_get(args).await?,
            CopilotCommands::Search(args) => cmd::copilot::search(args).await?,
            CopilotCommands::InteractionsExport(args) => cmd::copilot::interactions_export(args).await?,
            CopilotCommands::MeetingInsights(args) => cmd::copilot::meeting_insights(args).await?,
        },
        Commands::Tui(tui_cmd) => {
            match tui_cmd {
                TuiCommands::Dashboard => tui::run_tui()?,
                TuiCommands::Clients => tui::run_msp_menu().await?,
                TuiCommands::Configure => tui::run_interactive_menu().await?,
                TuiCommands::Quick => tui::quick_setting_change().await?,
                TuiCommands::Defender | TuiCommands::Exchange | TuiCommands::SharePoint | TuiCommands::Teams => {
                    let config = config::ConfigManager::load()?;
                    let active_tenant = config
                        .get_active_tenant()?
                        .ok_or_else(|| error::Error::ConfigError("No active tenant. Run 'ctl365 tui clients' to add a client or 'ctl365 login' first.".into()))?;

                    match tui_cmd {
                        TuiCommands::Defender => {
                            tui::configure_defender_interactive(&config, &active_tenant.name).await?;
                        }
                        TuiCommands::Exchange => {
                            tui::configure_exchange_interactive(&config, &active_tenant.name).await?;
                        }
                        TuiCommands::SharePoint => {
                            tui::configure_sharepoint_interactive(&config, &active_tenant.name).await?;
                        }
                        TuiCommands::Teams => {
                            tui::configure_teams_interactive(&config, &active_tenant.name).await?;
                        }
                        _ => {}
                    }
                }
            }
        },
    }

    Ok(())
}
