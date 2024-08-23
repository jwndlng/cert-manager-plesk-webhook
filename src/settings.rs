use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
pub struct CommonSettings {
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
pub struct PleskSettings {
    pub password: String,
    pub siteid: String,
    pub url: String,
    pub username: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub common: CommonSettings,
    pub plesk: PleskSettings,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let settings = Config::builder()
            .add_source(File::with_name("settings").required(false))
            .add_source(
                Environment::with_prefix("CMPW")
                .separator("_")
                .try_parsing(true)
            )
            .build()?;
        settings.try_deserialize()
    }
}
