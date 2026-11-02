use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_origin: String,
    pub database_path: PathBuf,
    pub log: String,
    #[serde(default = "default_pow_difficulty")]
    pub pow_difficulty: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().expect("valid default address"),
            public_origin: "http://localhost:8080".to_owned(),
            database_path: PathBuf::from("nxsd.db"),
            log: "nxsd=info".to_owned(),
            pow_difficulty: default_pow_difficulty(),
        }
    }
}

fn default_pow_difficulty() -> u8 {
    12
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = std::env::var("NXSD_CONFIG").unwrap_or_else(|_| "config/nxsd.toml".to_owned());
        let mut config = if Path::new(&path).exists() {
            Self::from_file(&path)?
        } else {
            Self::default()
        };
        config.apply_env()?;
        Ok(config)
    }

    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("reading config {}", path.as_ref().display()))?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text).context("parsing config")?;
        config.validate()?;
        Ok(config)
    }

    fn apply_env(&mut self) -> anyhow::Result<()> {
        if let Ok(value) = std::env::var("NXSD_LISTEN") {
            self.listen = value.parse().context("parsing NXSD_LISTEN")?;
        }
        if let Ok(value) = std::env::var("NXSD_PUBLIC_ORIGIN") {
            self.public_origin = value;
        }
        if let Ok(value) = std::env::var("NXSD_DATABASE_PATH") {
            self.database_path = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("NXSD_LOG") {
            self.log = value;
        }
        if let Ok(value) = std::env::var("NXSD_POW_DIFFICULTY") {
            self.pow_difficulty = value.parse().context("parsing NXSD_POW_DIFFICULTY")?;
        }
        self.validate()
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.public_origin.trim().is_empty() {
            anyhow::bail!("public_origin must not be empty");
        }
        crate::origin::Origin::parse(&self.public_origin)
            .context("public_origin must be canonical")?;
        if self.database_path.as_os_str().is_empty() {
            anyhow::bail!("database_path must not be empty");
        }
        if self.pow_difficulty > 24 {
            anyhow::bail!("pow_difficulty must be between 0 and 24");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parses_partial_toml_with_defaults() {
        let config = Config::from_toml(
            r#"
            public_origin = "https://provider.example"
            "#,
        )
        .expect("config parses");

        assert_eq!(config.public_origin, "https://provider.example");
        assert_eq!(config.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.log, "nxsd=info");
    }

    #[test]
    fn rejects_empty_origin() {
        let result = Config::from_toml(r#"public_origin = """#);
        assert!(result.is_err());
    }
}
