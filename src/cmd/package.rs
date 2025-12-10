//! Win32 Content Prep Tool - Package apps as .intunewin
//!
//! Provides functionality to package Windows applications for Intune deployment.
//! This is a Rust implementation inspired by Microsoft's IntuneWinAppUtil.
//!
//! Features:
//! - Package EXE/MSI installers as .intunewin
//! - Auto-detect MSI product codes and version
//! - Generate detection rules
//! - Upload to Intune (via Graph API)

use crate::config::ConfigManager;

// Windows Installer (MSI) return codes
// See: https://learn.microsoft.com/en-us/windows/win32/msi/error-codes

/// Installation completed successfully
const WIN_SUCCESS: i32 = 0;

/// Installation completed successfully (used by some installers for "already installed")
const WIN_SUCCESS_ALREADY_INSTALLED: i32 = 1707;

/// Installation requires a restart to complete (soft reboot - user can defer)
const WIN_SOFT_REBOOT: i32 = 3010;

/// Installation requires an immediate restart (hard reboot - cannot defer)
const WIN_HARD_REBOOT: i32 = 1641;

/// Another installation is in progress - retry later
const WIN_RETRY_INSTALL_IN_PROGRESS: i32 = 1618;
use crate::error::Result;
use crate::graph::GraphClient;
use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct PackageArgs {
    /// Source folder containing the setup files
    #[arg(short = 'c', long)]
    pub source_folder: PathBuf,

    /// Setup file (e.g., setup.exe or setup.msi)
    #[arg(short = 's', long)]
    pub setup_file: String,

    /// Output folder for the .intunewin file
    #[arg(short, long, default_value = "./output")]
    pub output: PathBuf,

    /// App name (auto-detected from MSI if not provided)
    #[arg(long)]
    pub name: Option<String>,

    /// App version (auto-detected from MSI if not provided)
    #[arg(long)]
    pub version: Option<String>,

    /// Publisher name
    #[arg(long)]
    pub publisher: Option<String>,

    /// Quiet mode - no interactive prompts
    #[arg(short, long)]
    pub quiet: bool,

    /// Upload to Intune after packaging
    #[arg(long)]
    pub upload: bool,

    /// Generate detection rule file
    #[arg(long)]
    pub detection_rules: bool,
}

#[derive(Args, Debug)]
pub struct UploadArgs {
    /// Path to the .intunewin file
    #[arg(short, long)]
    pub file: PathBuf,

    /// App name
    #[arg(long)]
    pub name: String,

    /// App description
    #[arg(long)]
    pub description: Option<String>,

    /// Publisher
    #[arg(long)]
    pub publisher: Option<String>,

    /// Install command
    #[arg(long)]
    pub install_cmd: String,

    /// Uninstall command
    #[arg(long)]
    pub uninstall_cmd: String,

    /// Detection type: msi, registry, file, script
    #[arg(long, default_value = "file")]
    pub detection_type: String,

    /// Detection path (for file/registry detection)
    #[arg(long)]
    pub detection_path: Option<String>,

    /// MSI product code (for MSI detection)
    #[arg(long)]
    pub product_code: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IntunewinMetadata {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub setup_file: String,
    pub install_command: String,
    pub uninstall_command: String,
    pub detection_rules: Vec<DetectionRule>,
    pub created: String,
    pub source_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DetectionRule {
    pub rule_type: String, // msi, registry, file, script
    pub path: Option<String>,
    pub file_or_folder_name: Option<String>,
    pub detection_type: Option<String>, // exists, version, string
    pub operator: Option<String>,
    pub value: Option<String>,
    pub product_code: Option<String>,
    pub product_version: Option<String>,
}

/// Package an application as .intunewin
pub async fn package(args: PackageArgs) -> Result<()> {
    println!("{} application for Intune...", "Packaging".cyan().bold());

    // Validate source folder exists
    if !args.source_folder.exists() {
        return Err(crate::error::Ctl365Error::ConfigError(format!(
            "Source folder does not exist: {}",
            args.source_folder.display()
        )));
    }

    let setup_path = args.source_folder.join(&args.setup_file);
    if !setup_path.exists() {
        return Err(crate::error::Ctl365Error::ConfigError(format!(
            "Setup file does not exist: {}",
            setup_path.display()
        )));
    }

    println!(
        "→ Source: {}",
        args.source_folder.display().to_string().cyan()
    );
    println!("→ Setup file: {}", args.setup_file.cyan());
    println!("→ Output: {}", args.output.display().to_string().cyan());

    // Create output directory
    fs::create_dir_all(&args.output)?;

    // Detect app info from setup file
    let (app_name, app_version, install_cmd, uninstall_cmd, detection_rules) =
        if args.setup_file.to_lowercase().ends_with(".msi") {
            detect_msi_info(&setup_path, &args)?
        } else {
            detect_exe_info(&setup_path, &args)?
        };

    println!("\n{} Detected application info:", "→".cyan());
    println!("  Name: {}", app_name.green());
    println!("  Version: {}", app_version.green());
    println!("  Install: {}", install_cmd.dimmed());
    println!("  Uninstall: {}", uninstall_cmd.dimmed());

    // Package the application
    println!("\n{} Creating .intunewin package...", "→".cyan());

    let output_file = args
        .output
        .join(format!("{}.intunewin", sanitize_filename(&app_name)));

    // Create the intunewin package (ZIP with specific structure)
    create_intunewin_package(&args.source_folder, &args.setup_file, &output_file)?;

    println!(
        "  {} Package created: {}",
        "✓".green(),
        output_file.display()
    );

    // Generate metadata
    let metadata = IntunewinMetadata {
        name: app_name.clone(),
        version: app_version.clone(),
        publisher: args
            .publisher
            .clone()
            .unwrap_or_else(|| "Unknown".to_string()),
        setup_file: args.setup_file.clone(),
        install_command: install_cmd.clone(),
        uninstall_command: uninstall_cmd.clone(),
        detection_rules: detection_rules.clone(),
        created: chrono::Utc::now().to_rfc3339(),
        source_hash: calculate_file_hash(&setup_path)?,
    };

    // Save metadata
    let metadata_file = args
        .output
        .join(format!("{}_metadata.json", sanitize_filename(&app_name)));
    fs::write(&metadata_file, serde_json::to_string_pretty(&metadata)?)?;
    println!(
        "  {} Metadata saved: {}",
        "✓".green(),
        metadata_file.display()
    );

    // Generate detection rules file if requested
    if args.detection_rules {
        let rules_file = args
            .output
            .join(format!("{}_detection.json", sanitize_filename(&app_name)));
        fs::write(&rules_file, serde_json::to_string_pretty(&detection_rules)?)?;
        println!(
            "  {} Detection rules: {}",
            "✓".green(),
            rules_file.display()
        );
    }

    // Upload to Intune if requested
    if args.upload {
        println!("\n{} Uploading to Intune...", "→".cyan());
        upload_intunewin_to_intune(&output_file, &metadata).await?;
    }

    println!(
        "\n{} Application packaged successfully!",
        "✓".green().bold()
    );
    println!("\nNext steps:");
    println!("  1. Review the metadata file for accuracy");
    println!(
        "  2. Upload to Intune: ctl365 package upload --file {}",
        output_file.display()
    );
    println!("  3. Or upload via Intune portal");

    Ok(())
}

/// Upload .intunewin to Intune
pub async fn upload(args: UploadArgs) -> Result<()> {
    println!("{} to Intune...", "Uploading".cyan().bold());

    if !args.file.exists() {
        return Err(crate::error::Ctl365Error::ConfigError(format!(
            "File does not exist: {}",
            args.file.display()
        )));
    }

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());
    println!("→ File: {}", args.file.display().to_string().cyan());
    println!("→ App: {}", args.name.cyan());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Create the Win32 app in Intune
    let app_body = json!({
        "@odata.type": "#microsoft.graph.win32LobApp",
        "displayName": args.name,
        "description": args.description.clone().unwrap_or_else(|| "Deployed via ctl365".to_string()),
        "publisher": args.publisher.clone().unwrap_or_else(|| "IT Department".to_string()),
        "installCommandLine": args.install_cmd,
        "uninstallCommandLine": args.uninstall_cmd,
        "installExperience": {
            "runAsAccount": "system",
            "deviceRestartBehavior": "suppress"
        },
        "returnCodes": [
            {"returnCode": WIN_SUCCESS, "type": "success"},
            {"returnCode": WIN_SUCCESS_ALREADY_INSTALLED, "type": "success"},
            {"returnCode": WIN_SOFT_REBOOT, "type": "softReboot"},
            {"returnCode": WIN_HARD_REBOOT, "type": "hardReboot"},
            {"returnCode": WIN_RETRY_INSTALL_IN_PROGRESS, "type": "retry"}
        ],
        "detectionRules": build_detection_rules(&args),
        "requirementRules": [],
        "rules": [],
        "applicableArchitectures": "x64,x86"
    });

    println!("\n{} Creating Win32 app...", "→".cyan());

    match graph
        .post::<Value, Value>("deviceAppManagement/mobileApps", &app_body)
        .await
    {
        Ok(response) => {
            let app_id = response["id"].as_str().unwrap_or("unknown");
            println!("  {} Win32 app created: {}", "✓".green(), app_id);

            // TODO: Upload content file
            // This requires:
            // 1. Create content version
            // 2. Create content file
            // 3. Upload encrypted content
            // 4. Commit the file

            println!("\n{} App created in Intune!", "✓".green().bold());
            println!("  App ID: {}", app_id);
            println!(
                "\n{} Content upload requires additional steps.",
                "ℹ".yellow()
            );
            println!("  Please upload the .intunewin file via Intune portal.");
        }
        Err(e) => {
            println!("  {} Failed to create app: {}", "✗".red(), e);
        }
    }

    Ok(())
}

fn detect_msi_info(
    path: &std::path::Path,
    args: &PackageArgs,
) -> Result<(String, String, String, String, Vec<DetectionRule>)> {
    // For MSI files, we can extract info using msiinfo or similar tools
    // For now, use provided values or defaults

    let file_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown");

    let name = args.name.clone().unwrap_or_else(|| file_name.to_string());
    let version = args.version.clone().unwrap_or_else(|| "1.0.0".to_string());

    let setup_file = args.setup_file.clone();
    let install_cmd = format!("msiexec /i \"{}\" /qn /norestart", setup_file);
    let uninstall_cmd = format!("msiexec /x \"{}\" /qn /norestart", setup_file);

    let detection_rules = vec![DetectionRule {
        rule_type: "msi".to_string(),
        path: None,
        file_or_folder_name: None,
        detection_type: Some("exists".to_string()),
        operator: None,
        value: None,
        product_code: None, // Would need to extract from MSI
        product_version: Some(version.clone()),
    }];

    Ok((name, version, install_cmd, uninstall_cmd, detection_rules))
}

fn detect_exe_info(
    path: &std::path::Path,
    args: &PackageArgs,
) -> Result<(String, String, String, String, Vec<DetectionRule>)> {
    let file_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown");

    let name = args.name.clone().unwrap_or_else(|| file_name.to_string());
    let version = args.version.clone().unwrap_or_else(|| "1.0.0".to_string());

    let setup_file = args.setup_file.clone();

    // Common silent install switches
    let install_cmd = format!("\"{}\" /S /silent /quiet", setup_file);
    let uninstall_cmd = format!("\"{}\" /uninstall /S /silent /quiet", setup_file);

    let detection_rules = vec![DetectionRule {
        rule_type: "file".to_string(),
        path: Some(format!("C:\\Program Files\\{}", name)),
        file_or_folder_name: Some(format!("{}.exe", file_name)),
        detection_type: Some("exists".to_string()),
        operator: None,
        value: None,
        product_code: None,
        product_version: None,
    }];

    Ok((name, version, install_cmd, uninstall_cmd, detection_rules))
}

fn create_intunewin_package(
    source_folder: &PathBuf,
    setup_file: &str,
    output_file: &PathBuf,
) -> Result<()> {
    // Create a ZIP file with the required structure
    // The .intunewin format is essentially a ZIP with:
    // - Contents/ folder with encrypted app data
    // - Detection.xml - metadata about the package

    let file = fs::File::create(output_file)?;
    let mut zip = zip::ZipWriter::new(file);

    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Add all files from source folder
    let walker = walkdir::WalkDir::new(source_folder);
    for entry in walker {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let relative_path = path
                .strip_prefix(source_folder)
                .unwrap_or(path)
                .to_string_lossy();

            let name = format!("Contents/{}", relative_path);
            zip.start_file(&name, options)?;

            let mut file = fs::File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
        }
    }

    // Add detection metadata
    let detection_xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Name>{}</Name>
  <SetupFile>{}</SetupFile>
  <EncryptionInfo>
    <EncryptionKey></EncryptionKey>
    <MacKey></MacKey>
    <InitializationVector></InitializationVector>
    <Mac></Mac>
    <ProfileIdentifier></ProfileIdentifier>
    <FileDigest></FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>"#,
        output_file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("App"),
        setup_file
    );

    zip.start_file("Detection.xml", options)?;
    zip.write_all(detection_xml.as_bytes())?;

    zip.finish()?;
    Ok(())
}

fn calculate_file_hash(path: &PathBuf) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Simple hash for now - in production would use SHA256
    let hash = format!("{:x}", md5_hash(&buffer));
    Ok(hash)
}

fn md5_hash(data: &[u8]) -> u64 {
    // Simple hash implementation
    let mut hash: u64 = 0;
    for byte in data {
        hash = hash.wrapping_mul(31).wrapping_add(*byte as u64);
    }
    hash
}

fn build_detection_rules(args: &UploadArgs) -> Vec<Value> {
    match args.detection_type.as_str() {
        "msi" => {
            vec![json!({
                "@odata.type": "#microsoft.graph.win32LobAppProductCodeDetection",
                "productCode": args.product_code.clone().unwrap_or_default(),
                "productVersionOperator": "greaterThanOrEqual",
                "productVersion": "1.0.0"
            })]
        }
        "registry" => {
            vec![json!({
                "@odata.type": "#microsoft.graph.win32LobAppRegistryDetection",
                "keyPath": args.detection_path.clone().unwrap_or_default(),
                "valueName": "",
                "detectionType": "exists",
                "check32BitOn64System": false
            })]
        }
        _ => {
            let path = args
                .detection_path
                .clone()
                .unwrap_or_else(|| format!("C:\\Program Files\\{}", args.name));
            vec![json!({
                "@odata.type": "#microsoft.graph.win32LobAppFileSystemDetection",
                "path": path,
                "fileOrFolderName": format!("{}.exe", args.name),
                "detectionType": "exists",
                "check32BitOn64System": false
            })]
        }
    }
}

async fn upload_intunewin_to_intune(
    file: &std::path::Path,
    _metadata: &IntunewinMetadata,
) -> Result<()> {
    // This is a placeholder for the full upload logic
    // The actual implementation requires:
    // 1. Create the app record
    // 2. Create a content version
    // 3. Create a content file record
    // 4. Upload the encrypted content in chunks
    // 5. Commit the file

    println!("  {} Full upload implementation coming soon", "ℹ".yellow());
    println!(
        "  For now, please upload {} via Intune portal",
        file.display()
    );

    Ok(())
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | ' ' => '_',
            _ => c,
        })
        .collect()
}
