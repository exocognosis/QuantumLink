use crate::error::{QlinkError, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl Ipv4Cidr {
    pub fn parse(input: &str) -> Result<Self> {
        let (addr, prefix) = input
            .split_once('/')
            .ok_or_else(|| QlinkError::Route(format!("missing prefix in {input}")))?;
        let address: Ipv4Addr = addr
            .parse()
            .map_err(|_| QlinkError::Route(format!("invalid IPv4 address {addr}")))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| QlinkError::Route(format!("invalid prefix in {input}")))?;
        if prefix > 32 {
            return Err(QlinkError::Route(format!("invalid prefix length {prefix}")));
        }

        let mask = mask(prefix);
        let network = Ipv4Addr::from(u32::from(address) & mask);
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let mask = mask(self.prefix);
        (u32::from(address) & mask) == u32::from(self.network)
    }

    pub fn subnet_mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(mask(self.prefix))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutePolicy {
    pub mode: RouteMode,
    pub protected_routes: Vec<Ipv4Cidr>,
    pub excluded_routes: Vec<Ipv4Cidr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    SplitTunnel,
    ProtectedPrefixesOnly,
    FullTunnel,
}

impl RoutePolicy {
    pub fn new(
        mode: RouteMode,
        protected_routes: &[String],
        excluded_routes: &[String],
    ) -> Result<Self> {
        let protected_routes = protected_routes
            .iter()
            .map(|route| Ipv4Cidr::parse(route))
            .collect::<Result<Vec<_>>>()?;
        let excluded_routes = excluded_routes
            .iter()
            .map(|route| Ipv4Cidr::parse(route))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            mode,
            protected_routes,
            excluded_routes,
        })
    }

    pub fn protects(&self, address: Ipv4Addr) -> bool {
        if self
            .excluded_routes
            .iter()
            .any(|route| route.contains(address))
        {
            return false;
        }
        match self.mode {
            RouteMode::FullTunnel => true,
            RouteMode::SplitTunnel | RouteMode::ProtectedPrefixesOnly => self
                .protected_routes
                .iter()
                .any(|route| route.contains(address)),
        }
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parse_normalizes_and_matches() {
        let cidr = Ipv4Cidr::parse("10.42.9.20/16").unwrap();
        assert_eq!(cidr.network, Ipv4Addr::new(10, 42, 0, 0));
        assert_eq!(cidr.subnet_mask(), Ipv4Addr::new(255, 255, 0, 0));
        assert!(cidr.contains(Ipv4Addr::new(10, 42, 1, 4)));
        assert!(!cidr.contains(Ipv4Addr::new(10, 43, 1, 4)));
    }

    #[test]
    fn route_policy_honors_exclusions() {
        let policy = RoutePolicy::new(
            RouteMode::SplitTunnel,
            &["10.0.0.0/8".to_string()],
            &["10.2.0.0/16".to_string()],
        )
        .unwrap();
        assert!(policy.protects(Ipv4Addr::new(10, 1, 0, 1)));
        assert!(!policy.protects(Ipv4Addr::new(10, 2, 0, 1)));
    }
}
