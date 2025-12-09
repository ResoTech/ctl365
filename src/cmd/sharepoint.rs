//! SharePoint CLI commands
//!
//! Commands for site provisioning, page management, and hub site configuration.

use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::GraphClient;
use crate::graph::sharepoint::{PageLayout, SharePointClient, SiteType};
use clap::Args;
use colored::Colorize;

// ============================================
// Site Commands
// ============================================

#[derive(Args, Debug)]
pub struct SiteCreateArgs {
    /// Display name for the site
    #[arg(short, long)]
    pub name: String,

    /// URL name (slug) for the site
    #[arg(short = 'u', long)]
    pub url_name: String,

    /// Site type: communication, team, team-no-group
    #[arg(short = 't', long, default_value = "communication")]
    pub site_type: String,

    /// Site description
    #[arg(short, long)]
    pub description: Option<String>,

    /// Owner user IDs or UPNs (comma-separated)
    #[arg(short, long)]
    pub owners: Option<String>,

    /// Make the site public (team sites only)
    #[arg(long)]
    pub public: bool,

    /// Dry run - show what would be created without creating
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct SiteListArgs {
    /// Search query to filter sites
    #[arg(short, long)]
    pub search: Option<String>,

    /// Output format: table, json
    #[arg(short, long, default_value = "table")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct SiteDeleteArgs {
    /// Site ID to delete
    #[arg(short, long)]
    pub id: String,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct SiteGetArgs {
    /// Site ID
    #[arg(short, long, conflicts_with_all = ["hostname", "path"])]
    pub id: Option<String>,

    /// Site hostname (e.g., contoso.sharepoint.com)
    #[arg(long, requires = "path")]
    pub hostname: Option<String>,

    /// Site path (e.g., /sites/marketing)
    #[arg(long, requires = "hostname")]
    pub path: Option<String>,
}

// ============================================
// Page Commands
// ============================================

#[derive(Args, Debug)]
pub struct PageCreateArgs {
    /// Site ID where the page will be created
    #[arg(short, long)]
    pub site_id: String,

    /// Page name (without .aspx extension)
    #[arg(short, long)]
    pub name: String,

    /// Page title
    #[arg(short, long)]
    pub title: String,

    /// Page layout: article, home, vertical-section
    #[arg(short, long, default_value = "article")]
    pub layout: String,

    /// Publish the page immediately after creation
    #[arg(long)]
    pub publish: bool,

    /// Dry run - show what would be created without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct PageListArgs {
    /// Site ID
    #[arg(short, long)]
    pub site_id: String,

    /// Output format: table, json
    #[arg(short, long, default_value = "table")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct PageDeleteArgs {
    /// Site ID
    #[arg(short, long)]
    pub site_id: String,

    /// Page ID
    #[arg(short, long)]
    pub page_id: String,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

// ============================================
// Hub Site Commands
// ============================================

#[derive(Args, Debug)]
pub struct HubListArgs {
    /// Output format: table, json
    #[arg(short, long, default_value = "table")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct HubSetArgs {
    /// Site ID to register as hub
    #[arg(short, long)]
    pub site_id: String,

    /// Hub site title
    #[arg(short, long)]
    pub title: String,

    /// Dry run - show what would be registered without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct HubJoinArgs {
    /// Site ID to join to hub
    #[arg(short, long)]
    pub site_id: String,

    /// Hub site ID to join
    #[arg(short = 'b', long)]
    pub hub_id: String,

    /// Dry run - show what would be joined without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

// ============================================
// Command Implementations
// ============================================

pub async fn site_create(args: SiteCreateArgs) -> Result<()> {
    let site_type = match args.site_type.to_lowercase().as_str() {
        "communication" => SiteType::Communication,
        "team" => SiteType::Team,
        "team-no-group" | "teamnogroup" => SiteType::TeamNoGroup,
        _ => {
            eprintln!(
                "{} Invalid site type '{}'. Use: communication, team, or team-no-group",
                "Error:".red().bold(),
                args.site_type
            );
            return Ok(());
        }
    };

    println!(
        "{} Creating {} '{}'...",
        "SharePoint".cyan().bold(),
        site_type.display_name(),
        args.name
    );

    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("  Display Name: {}", args.name);
        println!("  URL Name: {}", args.url_name);
        println!("  Type: {}", site_type.display_name());
        if let Some(desc) = &args.description {
            println!("  Description: {}", desc);
        }
        if let Some(owners) = &args.owners {
            println!("  Owners: {}", owners);
        }
        println!("  Public: {}", args.public);
        return Ok(());
    }

    if !args.yes {
        println!("\nThis will create a new SharePoint site.");
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    let owners = args
        .owners
        .map(|o| o.split(',').map(|s| s.trim().to_string()).collect());

    let result = sp_client
        .create_site(
            &args.name,
            &args.url_name,
            site_type,
            args.description.as_deref(),
            owners,
            Some(args.public),
        )
        .await?;

    println!("\n{} Site created successfully!", "Success".green().bold());
    println!("  ID: {}", result.id);
    if let Some(url) = result.web_url {
        println!("  URL: {}", url);
    }

    Ok(())
}

pub async fn site_list(args: SiteListArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    println!("{} Fetching sites...", "SharePoint".cyan().bold());

    let sites = match &args.search {
        Some(query) => sp_client.search_sites(query).await?,
        None => sp_client.list_sites().await?,
    };

    if sites.is_empty() {
        println!("No sites found.");
        return Ok(());
    }

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&sites)?);
        return Ok(());
    }

    println!(
        "\n{} SharePoint Sites ({} found)",
        "=".repeat(60),
        sites.len()
    );
    println!("{:<40} {:<50} {}", "NAME".bold(), "URL".bold(), "ID".bold());
    println!("{}", "-".repeat(120));

    for site in sites {
        let name = site.display_name.unwrap_or_else(|| "-".to_string());
        let url = site.web_url.unwrap_or_else(|| "-".to_string());
        let id = &site.id;
        println!("{:<40} {:<50} {}", name, url, id);
    }

    Ok(())
}

pub async fn site_get(args: SiteGetArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    let site = if let Some(id) = args.id {
        sp_client.get_site(&id).await?
    } else if let (Some(hostname), Some(path)) = (args.hostname, args.path) {
        sp_client.get_site_by_url(&hostname, &path).await?
    } else {
        eprintln!(
            "{} Must specify either --id or both --hostname and --path",
            "Error:".red().bold()
        );
        return Ok(());
    };

    println!("\n{} Site Details", "SharePoint".cyan().bold());
    println!("{}", "=".repeat(60));
    println!("  ID: {}", site.id);
    if let Some(name) = site.display_name {
        println!("  Display Name: {}", name);
    }
    if let Some(name) = site.name {
        println!("  Name: {}", name);
    }
    if let Some(url) = site.web_url {
        println!("  URL: {}", url);
    }
    if let Some(desc) = site.description {
        println!("  Description: {}", desc);
    }
    if let Some(created) = site.created_date_time {
        println!("  Created: {}", created);
    }

    Ok(())
}

pub async fn site_delete(args: SiteDeleteArgs) -> Result<()> {
    if !args.yes {
        println!(
            "{} This will permanently delete the site.",
            "Warning:".yellow().bold()
        );
        print!("Are you sure? Type 'DELETE' to confirm: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "DELETE" {
            println!("Aborted.");
            return Ok(());
        }
    }

    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    println!(
        "{} Deleting site {}...",
        "SharePoint".cyan().bold(),
        args.id
    );
    sp_client.delete_site(&args.id).await?;

    println!("{} Site deleted successfully!", "Success".green().bold());

    Ok(())
}

pub async fn page_create(args: PageCreateArgs) -> Result<()> {
    let layout = match args.layout.to_lowercase().as_str() {
        "article" => PageLayout::Article,
        "home" => PageLayout::Home,
        "vertical-section" | "verticalsection" => PageLayout::VerticalSection,
        _ => {
            eprintln!(
                "{} Invalid layout '{}'. Use: article, home, or vertical-section",
                "Error:".red().bold(),
                args.layout
            );
            return Ok(());
        }
    };

    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("{} Would create page:", "→".cyan());
        println!("  Site ID: {}", args.site_id);
        println!("  Name: {}", args.name);
        println!("  Title: {}", args.title);
        println!("  Layout: {}", args.layout);
        println!("  Publish: {}", args.publish);
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        println!("\nThis will create a new SharePoint page.");
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    println!(
        "{} Creating page '{}' in site {}...",
        "SharePoint".cyan().bold(),
        args.title,
        args.site_id
    );

    let page = sp_client
        .create_page(&args.site_id, &args.name, &args.title, layout)
        .await?;

    if args.publish {
        println!("Publishing page...");
        sp_client.publish_page(&args.site_id, &page.id).await?;
    }

    println!("\n{} Page created successfully!", "Success".green().bold());
    println!("  ID: {}", page.id);
    if let Some(url) = page.web_url {
        println!("  URL: {}", url);
    }

    Ok(())
}

pub async fn page_list(args: PageListArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    println!(
        "{} Fetching pages for site {}...",
        "SharePoint".cyan().bold(),
        args.site_id
    );

    let pages = sp_client.list_pages(&args.site_id).await?;

    if pages.is_empty() {
        println!("No pages found.");
        return Ok(());
    }

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&pages)?);
        return Ok(());
    }

    println!("\n{} Pages ({} found)", "=".repeat(60), pages.len());
    println!(
        "{:<40} {:<20} {}",
        "TITLE".bold(),
        "LAYOUT".bold(),
        "ID".bold()
    );
    println!("{}", "-".repeat(100));

    for page in pages {
        let title = page.title.unwrap_or_else(|| "-".to_string());
        let layout = page.page_layout.unwrap_or_else(|| "-".to_string());
        println!("{:<40} {:<20} {}", title, layout, page.id);
    }

    Ok(())
}

pub async fn page_delete(args: PageDeleteArgs) -> Result<()> {
    if !args.yes {
        println!(
            "{} This will permanently delete the page.",
            "Warning:".yellow().bold()
        );
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    println!(
        "{} Deleting page {}...",
        "SharePoint".cyan().bold(),
        args.page_id
    );
    sp_client.delete_page(&args.site_id, &args.page_id).await?;

    println!("{} Page deleted successfully!", "Success".green().bold());

    Ok(())
}

pub async fn hub_list(args: HubListArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    println!("{} Fetching hub sites...", "SharePoint".cyan().bold());

    let hubs = sp_client.list_hub_sites().await?;

    if hubs.is_empty() {
        println!("No hub sites found.");
        return Ok(());
    }

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&hubs)?);
        return Ok(());
    }

    println!("\n{} Hub Sites ({} found)", "=".repeat(60), hubs.len());
    println!(
        "{:<40} {:<50} {}",
        "TITLE".bold(),
        "URL".bold(),
        "ID".bold()
    );
    println!("{}", "-".repeat(120));

    for hub in hubs {
        let title = hub.title.unwrap_or_else(|| "-".to_string());
        let url = hub.site_url.unwrap_or_else(|| "-".to_string());
        println!("{:<40} {:<50} {}", title, url, hub.id);
    }

    Ok(())
}

pub async fn hub_set(args: HubSetArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("{} Would register hub site:", "→".cyan());
        println!("  Site ID: {}", args.site_id);
        println!("  Title: {}", args.title);
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        println!("\nThis will register the site as a hub site.");
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    println!(
        "{} Registering site {} as hub '{}'...",
        "SharePoint".cyan().bold(),
        args.site_id,
        args.title
    );

    let hub = sp_client
        .register_hub_site(&args.site_id, &args.title)
        .await?;

    println!(
        "\n{} Hub site registered successfully!",
        "Success".green().bold()
    );
    println!("  Hub ID: {}", hub.id);

    Ok(())
}

pub async fn hub_join(args: HubJoinArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Ctl365Error::ConfigError(
            "No active tenant. Run 'ctl365 tenant switch <name>' first.".into(),
        )
    })?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("{} Would join site to hub:", "→".cyan());
        println!("  Site ID: {}", args.site_id);
        println!("  Hub ID: {}", args.hub_id);
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        println!("\nThis will join the site to the hub.");
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let sp_client = SharePointClient::new(&client);

    println!(
        "{} Joining site {} to hub {}...",
        "SharePoint".cyan().bold(),
        args.site_id,
        args.hub_id
    );

    sp_client.join_hub_site(&args.site_id, &args.hub_id).await?;

    println!(
        "\n{} Site joined to hub successfully!",
        "Success".green().bold()
    );

    Ok(())
}
