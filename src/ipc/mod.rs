mod mitmproxy_ipc;
pub use mitmproxy_ipc::*;

use crate::intercept_conf;
use std::net::{AddrParseError, IpAddr, SocketAddr};
use std::str::FromStr;

impl TryFrom<&Address> for SocketAddr {
    type Error = AddrParseError;

    fn try_from(address: &Address) -> Result<Self, Self::Error> {
        let ip = IpAddr::from_str(&address.host)?;
        Ok(SocketAddr::from((ip, address.port as u16)))
    }
}
impl From<SocketAddr> for Address {
    fn from(val: SocketAddr) -> Self {
        let version = if val.is_ipv4() {
            "4".to_string()
        } else {
            "6".to_string()
        };
        Address {   
            host: val.ip().to_string(),
            port: val.port() as u32,
            version: version,
            src_port: val.port() as u32,
        }
    }
}

impl From<intercept_conf::InterceptConf> for InterceptConf {
    fn from(conf: intercept_conf::InterceptConf) -> Self {
        InterceptConf {
            default: conf.default(),
            actions: conf.actions(),
            agent_pid: conf.agent_pid().unwrap_or(0),
            mode: conf.mode().to_string(),
        }
    }
}

impl TryFrom<InterceptConf> for intercept_conf::InterceptConf {
    type Error = anyhow::Error;

    fn try_from(conf: InterceptConf) -> Result<Self, Self::Error> {
        let mut tokens: Vec<String> = conf.actions.iter().cloned().collect();
        // include mode token so TryFrom<Vec<T>> in intercept_conf will parse it
        if !conf.mode.is_empty() {
            tokens.push(format!("mode={}", conf.mode));
        }
        let mut intercept_conf = intercept_conf::InterceptConf::try_from(tokens)?;
        
        // Set agent_pid if it's not 0 (protobuf default)
        if conf.agent_pid != 0 {
            intercept_conf.set_agent_pid(conf.agent_pid);
        }
        
        Ok(intercept_conf)
    }
}
