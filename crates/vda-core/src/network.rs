//! Network allowlists and target-address validation.
use crate::error::ApiError;
use ipnet::IpNet;
use std::net::IpAddr;

/// Validate a bounded list of network ranges.
pub fn parse_cidrs(values: &[String]) -> Result<Vec<IpNet>, ApiError> {
    if values.len() > 128 {
        return Err(ApiError::validation("Too many CIDRs"));
    }
    values
        .iter()
        .map(|s| s.parse().map_err(|_| ApiError::validation("Invalid CIDR")))
        .collect()
}
/// Empty allowlists allow all; independent allowlists are intersected by callers.
pub fn allowed(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    cidrs.is_empty() || cidrs.iter().any(|net| net.contains(&ip))
}
/// Refuse cloud metadata and link-local addresses, and loopback unless explicitly enabled.
pub fn target_ip_allowed(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_link_local()
                && v.octets().first() != Some(&0)
                && v != std::net::Ipv4Addr::new(100, 100, 100, 200)
                && !v.is_multicast()
                && !v.is_broadcast()
                && (!v.is_loopback() || allow_private)
        }
        IpAddr::V6(v) => {
            if v.is_loopback() {
                return allow_private;
            }
            if let Some(v4) = v.to_ipv4() {
                return target_ip_allowed(v4.into(), allow_private);
            }
            let octets = v.octets();
            if octets.get(..12) == Some(&[0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]) {
                if let Some(tail) = octets.get(12..) {
                    if let Ok(bytes) = <[u8; 4]>::try_from(tail) {
                        return target_ip_allowed(
                            std::net::Ipv4Addr::from(bytes).into(),
                            allow_private,
                        );
                    }
                }
            }
            !v.is_unicast_link_local()
                && !v.is_unspecified()
                && !v.is_multicast()
                && v.to_string() != "fd00:ec2::254"
                && (!v.is_loopback() || allow_private)
        }
    }
}
/// Resolve every address and refuse a mixed safe/unsafe DNS answer.
pub async fn validate_host(host: &str, port: u16, allow_private: bool) -> Result<(), ApiError> {
    crate::sanitation::text(host)?;
    if host.is_empty()
        || host.len() > 253
        || port == 0
        || host
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '@' | '#' | '?'))
    {
        return Err(ApiError::validation("Invalid target host or port"));
    }
    let addresses = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| ApiError::validation("Target DNS lookup timed out"))?
    .map_err(|_| ApiError::validation("Target host cannot be resolved"))?;
    let mut found = false;
    for addr in addresses {
        found = true;
        if !target_ip_allowed(addr.ip(), allow_private) {
            return Err(ApiError::validation("Target address is prohibited"));
        }
    }
    if !found {
        return Err(ApiError::validation("Target host has no addresses"));
    }
    Ok(())
}
