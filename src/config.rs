use crate::args::Args;
use crate::errors::*;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_URL: &str = "https://security.archlinux.org/all.json";

pub struct Config {
    pub source: String,
    pub proxy: Option<String>,
}

impl Config {
    pub fn load(args: &Args) -> Result<Self> {
        let mut merged = ConfigFile::default();

        let mut configs = vec![PathBuf::from("/etc/arch-audit/settings.toml")];
        if let Some(dir) = dirs_next::config_dir() {
            let path = dir.join("arch-audit/settings.toml");
            configs.push(path);
        }

        for path in configs {
            let c = ConfigFile::load_from(&path)
                .with_context(|| anyhow!("Failed to load config file: {:?}", path))?;
            if let Some(config) = c {
                debug!("Applying config from {:?}", path);
                merged.update(config);
            }
        }

        let mut config = Self {
            source: merged.network.source.unwrap_or_else(|| DEFAULT_URL.into()),
            proxy: merged.network.proxy,
        };

        if let Some(source) = &args.source {
            config.source = source.to_string();
        }

        if let Some(proxy) = &args.proxy {
            config.proxy = Some(proxy.to_string());
        }

        if args.no_proxy {
            config.proxy = None;
        }

        Ok(config)
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct ConfigFile {
    network: NetworkConfigFile,
}

impl ConfigFile {
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Option<Self>> {
        let path = path.as_ref();
        if path.exists() {
            let file = fs::read_to_string(path)?;
            let cf = toml::from_str(&file)?;
            Ok(Some(cf))
        } else {
            Ok(None)
        }
    }

    pub fn update(&mut self, config: Self) {
        Self::update_field(&mut self.network.source, config.network.source);
        Self::update_field(&mut self.network.proxy, config.network.proxy);
    }

    pub fn update_field<T: PartialEq>(old: &mut Option<T>, new: Option<T>) {
        if let Some(new) = new {
            *old = Some(new);
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct NetworkConfigFile {
    source: Option<String>,
    proxy: Option<String>,
}
