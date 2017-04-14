use std::default::Default;
use std::net::SocketAddr;
use std::fs::File;
use errors::*;
use serde_json;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub listen: Listen,
    #[serde(default)]
    pub local: Local,
    #[serde(default)]
    pub correlation: Correlation,
    #[serde(default)]
    pub service: Service,
}

impl Config {
    pub fn from_file(filename: &str) -> Result<Config> {
        let f = File::open(filename).chain_err(|| format!("Could not load config at: {}", filename))?;
        serde_json::from_reader(f).chain_err(|| "Config file is not valid")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Listen {
    pub port: u16,
    pub bind: String
}

impl Listen {
    pub fn to_addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.bind, self.port).parse().chain_err(|| format!("Invalid address: {}:{}", self.bind, self.port))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Local {
    pub skew: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Correlation {
    pub enable: bool,
    pub header: String
}

#[derive(Debug, Clone, Deserialize)]
pub struct Service {
    pub port: u16,
    pub bind: String,
    pub scheme: String
}

impl Default for Listen {
    fn default() -> Listen {
        Listen {
            port: 9300,
            bind: "127.0.0.1".to_owned()
        }
    }
}

impl Default for Local {
    fn default() -> Local {
        Local {
            skew: 15 * 60
        }
    }
}

impl Default for Correlation {
    fn default() -> Correlation {
        Correlation {
            enable: true,
            header: "X-Request-Identifier".to_owned()
        }
    }
}

impl Default for Service {
    fn default() -> Service {
        Service {
            port: 9301,
            bind: "localhost".to_owned(),
            scheme: "http".to_owned()
        }
    }
}