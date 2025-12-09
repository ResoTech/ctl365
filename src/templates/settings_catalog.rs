//! Settings Catalog support for modern Intune configuration
//!
//! Settings Catalog is the modern way to configure devices in Intune,
//! replacing older device configuration profiles with a more flexible
//! and granular settings-based approach.

#![allow(dead_code)]

use serde_json::{json, Value};

/// Settings Catalog policy type
#[derive(Debug, Clone)]
pub struct SettingsCatalogPolicy {
    pub name: String,
    pub description: String,
    pub platform: Platform,
    pub technologies: Technologies,
    pub template_reference: Option<TemplateReference>,
    pub settings: Vec<Setting>,
}

#[derive(Debug, Clone)]
pub enum Platform {
    Windows10,
    MacOS,
    IOS,
    Android,
}

#[derive(Debug, Clone)]
pub enum Technologies {
    Mdm,
    WindowsLaps,
    EndpointPrivilegeManagement,
}

#[derive(Debug, Clone)]
pub struct TemplateReference {
    pub template_id: String,
    pub template_family: TemplateFamily,
    pub template_display_name: String,
    pub template_display_version: String,
}

#[derive(Debug, Clone)]
pub enum TemplateFamily {
    EndpointSecurityDiskEncryption,
    EndpointSecurityAntivirus,
    EndpointSecurityFirewall,
    EndpointSecurityAttackSurfaceReduction,
    EndpointSecurityAccountProtection,
    None,
}

/// Represents a single setting in Settings Catalog
#[derive(Debug, Clone)]
pub struct Setting {
    pub setting_definition_id: String,
    pub setting_instance: SettingInstance,
}

#[derive(Debug, Clone)]
pub enum SettingInstance {
    Choice(ChoiceSettingInstance),
    Simple(SimpleSettingInstance),
    Group(GroupSettingInstance),
    GroupCollection(GroupSettingCollectionInstance),
}

#[derive(Debug, Clone)]
pub struct ChoiceSettingInstance {
    pub setting_definition_id: String,
    pub value: String,
    pub children: Vec<Setting>,
}

#[derive(Debug, Clone)]
pub struct SimpleSettingInstance {
    pub setting_definition_id: String,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct GroupSettingInstance {
    pub setting_definition_id: String,
    pub children: Vec<Setting>,
}

#[derive(Debug, Clone)]
pub struct GroupSettingCollectionInstance {
    pub setting_definition_id: String,
    pub group_setting_collection_value: Vec<GroupSettingValue>,
}

#[derive(Debug, Clone)]
pub struct GroupSettingValue {
    pub children: Vec<Setting>,
}

impl SettingsCatalogPolicy {
    /// Convert to Graph API JSON payload
    pub fn to_json(&self) -> Value {
        let mut policy = json!({
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
            "name": self.name,
            "description": self.description,
            "platforms": self.platform.to_string(),
            "technologies": self.technologies.to_string(),
            "settings": self.settings.iter().map(|s| s.to_json()).collect::<Vec<_>>(),
        });

        if let Some(template_ref) = &self.template_reference {
            policy["templateReference"] = json!({
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicyTemplateReference",
                "templateId": template_ref.template_id,
                "templateFamily": template_ref.template_family.to_string(),
                "templateDisplayName": template_ref.template_display_name,
                "templateDisplayVersion": template_ref.template_display_version,
            });
        }

        policy
    }
}

impl Setting {
    pub fn to_json(&self) -> Value {
        // Settings must be wrapped in deviceManagementConfigurationSetting
        // as per Microsoft Graph API spec and real Intune exports
        json!({
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": self.setting_instance.to_json(),
        })
    }
}

impl SettingInstance {
    pub fn to_json(&self) -> Value {
        match self {
            SettingInstance::Choice(choice) => json!({
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": choice.setting_definition_id,
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": choice.value,
                    "children": choice.children.iter().map(|c| c.setting_instance.to_json()).collect::<Vec<_>>(),
                }
            }),
            SettingInstance::Simple(simple) => json!({
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": simple.setting_definition_id,
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                    "value": simple.value,
                }
            }),
            SettingInstance::Group(group) => json!({
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingInstance",
                "settingDefinitionId": group.setting_definition_id,
                "groupSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingValue",
                    "children": group.children.iter().map(|c| c.setting_instance.to_json()).collect::<Vec<_>>(),
                }
            }),
            SettingInstance::GroupCollection(collection) => json!({
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                "settingDefinitionId": collection.setting_definition_id,
                "groupSettingCollectionValue": collection.group_setting_collection_value.iter().map(|gsv| {
                    json!({
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingValue",
                        "children": gsv.children.iter().map(|c| c.setting_instance.to_json()).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
            }),
        }
    }
}

impl ToString for Platform {
    fn to_string(&self) -> String {
        match self {
            Platform::Windows10 => "windows10".to_string(),
            Platform::MacOS => "macOS".to_string(),
            Platform::IOS => "iOS".to_string(),
            Platform::Android => "android".to_string(),
        }
    }
}

impl ToString for Technologies {
    fn to_string(&self) -> String {
        match self {
            Technologies::Mdm => "mdm".to_string(),
            Technologies::WindowsLaps => "windowsLaps".to_string(),
            Technologies::EndpointPrivilegeManagement => "endpointPrivilegeManagement".to_string(),
        }
    }
}

impl ToString for TemplateFamily {
    fn to_string(&self) -> String {
        match self {
            TemplateFamily::EndpointSecurityDiskEncryption => "endpointSecurityDiskEncryption".to_string(),
            TemplateFamily::EndpointSecurityAntivirus => "endpointSecurityAntivirus".to_string(),
            TemplateFamily::EndpointSecurityFirewall => "endpointSecurityFirewall".to_string(),
            TemplateFamily::EndpointSecurityAttackSurfaceReduction => "endpointSecurityAttackSurfaceReduction".to_string(),
            TemplateFamily::EndpointSecurityAccountProtection => "endpointSecurityAccountProtection".to_string(),
            TemplateFamily::None => "none".to_string(),
        }
    }
}

/// Helper to create a choice setting
pub fn choice_setting(definition_id: &str, value: &str) -> Setting {
    Setting {
        setting_definition_id: definition_id.to_string(),
        setting_instance: SettingInstance::Choice(ChoiceSettingInstance {
            setting_definition_id: definition_id.to_string(),
            value: value.to_string(),
            children: vec![],
        }),
    }
}

/// Helper to create a choice setting with children
pub fn choice_setting_with_children(definition_id: &str, value: &str, children: Vec<Setting>) -> Setting {
    Setting {
        setting_definition_id: definition_id.to_string(),
        setting_instance: SettingInstance::Choice(ChoiceSettingInstance {
            setting_definition_id: definition_id.to_string(),
            value: value.to_string(),
            children,
        }),
    }
}

/// Helper to create an integer setting
pub fn integer_setting(definition_id: &str, value: i32) -> Setting {
    Setting {
        setting_definition_id: definition_id.to_string(),
        setting_instance: SettingInstance::Simple(SimpleSettingInstance {
            setting_definition_id: definition_id.to_string(),
            value: json!(value),
        }),
    }
}

/// Helper to create a string setting
pub fn string_setting(definition_id: &str, value: &str) -> Setting {
    Setting {
        setting_definition_id: definition_id.to_string(),
        setting_instance: SettingInstance::Simple(SimpleSettingInstance {
            setting_definition_id: definition_id.to_string(),
            value: json!(value),
        }),
    }
}

/// Helper to create a group setting collection (for ASR rules, WHfB, etc.)
pub fn group_collection_setting(definition_id: &str, collection_values: Vec<Vec<Setting>>) -> Setting {
    Setting {
        setting_definition_id: definition_id.to_string(),
        setting_instance: SettingInstance::GroupCollection(GroupSettingCollectionInstance {
            setting_definition_id: definition_id.to_string(),
            group_setting_collection_value: collection_values
                .into_iter()
                .map(|children| GroupSettingValue { children })
                .collect(),
        }),
    }
}
