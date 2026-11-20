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
/// Whether a database target may be at `ip`.
///
/// Refuses cloud metadata and platform addresses, link-local, zero-network,
/// multicast and broadcast addresses, and loopback unless `allow_private`.
/// Private (RFC 1918) and non-global IPv6 addresses are allowed, because
/// databases live on private networks. An IPv6 address that stands for an
/// IPv4 one (IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64, 6to4) is
/// judged by that IPv4 address, exactly as its plain form.
pub fn target_ip_allowed(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_link_local()
                && v.octets().first() != Some(&0)
                && v != std::net::Ipv4Addr::new(100, 100, 100, 200)
                && v != AZURE_PLATFORM
                && !v.is_multicast()
                && !v.is_broadcast()
                && (!v.is_loopback() || allow_private)
        }
        IpAddr::V6(v) => {
            if v.is_loopback() {
                return allow_private;
            }
            if let Some(inner) = embedded_v4(v).or_else(|| local_nat64_v4(v)) {
                return target_ip_allowed(inner.into(), allow_private);
            }
            !v.is_unicast_link_local()
                && !v.is_unspecified()
                && !v.is_multicast()
                && v.to_string() != "fd00:ec2::254"
        }
    }
}
/// The Azure platform address, reachable from every Azure host.
const AZURE_PLATFORM: std::net::Ipv4Addr = std::net::Ipv4Addr::new(168, 63, 129, 16);
/// Whether an outbound notice may be sent to `ip`.
///
/// A notice goes to an address that an administrator typed, so it is held to
/// more than a database target: besides everything [`target_ip_allowed`]
/// refuses, an address must be public. For IPv4 that means outside the
/// private (RFC 1918), carrier-grade NAT, documentation, benchmark, relay
/// and reserved ranges and not a cloud platform address. For IPv6 it means
/// inside global unicast `2000::/3` and outside the special blocks in it. An
/// IPv6 address that stands for an IPv4 one (IPv4-mapped, IPv4-compatible,
/// IPv4-translated, NAT64, 6to4) is judged by that IPv4 address.
/// `allow_private` (local development) lifts only this second part.
pub fn webhook_ip_allowed(ip: IpAddr, allow_private: bool) -> bool {
    if !target_ip_allowed(ip, allow_private) {
        return false;
    }
    if allow_private {
        return true;
    }
    match ip {
        IpAddr::V4(v) => public_v4(v),
        IpAddr::V6(v) => match embedded_v4(v) {
            Some(inner) => webhook_ip_allowed(inner.into(), false),
            None => global_v6(v),
        },
    }
}
fn public_v4(v: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = v.octets();
    !(v.is_private()
        || v.is_loopback()
        || v.is_link_local()
        || v.is_documentation()
        || v.is_unspecified()
        || v.is_broadcast()
        || v.is_multicast()
        // Carrier-grade NAT 100.64.0.0/10.
        || (a == 100 && (b & 0xc0) == 64)
        // Protocol assignments 192.0.0.0/24, the retired 6to4 relays
        // 192.88.99.0/24 and benchmarking 198.18.0.0/15.
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b & 0xfe) == 18)
        // Reserved 240.0.0.0/4.
        || a >= 240
        || v == AZURE_PLATFORM)
}
/// The IPv4 address that an IPv6 address stands for, if it stands for one.
fn embedded_v4(v: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let [a, b, c, d, e, f, g, h] = v.segments();
    let tail = std::net::Ipv4Addr::new((g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8);
    match (a, b, c, d, e, f) {
        // IPv4-mapped ::ffff:a.b.c.d, IPv4-compatible ::a.b.c.d and
        // IPv4-translated ::ffff:0:a.b.c.d.
        (0, 0, 0, 0, 0, 0xffff) | (0, 0, 0, 0, 0, 0) | (0, 0, 0, 0, 0xffff, 0) => Some(tail),
        // NAT64 64:ff9b::/96.
        (0x0064, 0xff9b, 0, 0, 0, 0) => Some(tail),
        // 6to4 2002:a.b.c.d::/48.
        (0x2002, ..) => Some(std::net::Ipv4Addr::new(
            (b >> 8) as u8,
            b as u8,
            (c >> 8) as u8,
            c as u8,
        )),
        _ => None,
    }
}
/// The IPv4 address behind a local-use NAT64 address `64:ff9b:1::a.b.c.d`
/// (the `/96` form inside `64:ff9b:1::/48`). Only a database target needs
/// it: a notice never goes to this block, which is not global unicast.
fn local_nat64_v4(v: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let [a, b, c, d, e, f, g, h] = v.segments();
    ((a, b, c, d, e, f) == (0x0064, 0xff9b, 1, 0, 0, 0))
        .then(|| std::net::Ipv4Addr::new((g >> 8) as u8, g as u8, (h >> 8) as u8, h as u8))
}
/// A plain IPv6 address that a public host can have: global unicast
/// `2000::/3` without the blocks set aside inside it.
fn global_v6(v: std::net::Ipv6Addr) -> bool {
    let [a, b, ..] = v.segments();
    (a & 0xe000) == 0x2000
        // 2001::/23 is for protocols, not hosts: Teredo, benchmarking
        // 2001:2::/48, ORCHID 2001:10::/28 and 2001:20::/28, and the rest.
        && !(a == 0x2001 && b < 0x0200)
        // Documentation 2001:db8::/32 and 3fff::/20.
        && !(a == 0x2001 && b == 0x0db8)
        && !(a == 0x3fff && (b & 0xf000) == 0)
        // Segment routing 5f00::/16.
        && a != 0x5f00
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        match text.parse() {
            Ok(ip) => ip,
            Err(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Every IPv6 form that stands for the IPv4 address `a.b.c.d`.
    fn wrapped(v4: &str) -> Vec<String> {
        let o = match v4.parse::<std::net::Ipv4Addr>() {
            Ok(v) => v.octets(),
            Err(_) => [0; 4],
        };
        let (hi, lo) = (
            format!("{:02x}{:02x}", o[0], o[1]),
            format!("{:02x}{:02x}", o[2], o[3]),
        );
        vec![
            format!("::ffff:{v4}"),
            format!("::{v4}"),
            format!("::ffff:0:{v4}"),
            format!("::ffff:0:{hi}:{lo}"),
            format!("64:ff9b::{hi}:{lo}"),
            format!("64:ff9b:1::{hi}:{lo}"),
            format!("2002:{hi}:{lo}::"),
            format!("2002:{hi}:{lo}::1"),
        ]
    }

    #[test]
    fn a_database_target_keeps_its_plain_rule() {
        for allowed in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "1.1.1.1",
            "168.63.129.15",
            "fd12:3456:789a::1",
            "fc00::1",
            "fec0::1",
            "2606:4700:4700::1111",
            "2001:db8::1",
            "64:ff9b:1:1::1",
        ] {
            assert!(target_ip_allowed(ip(allowed), false), "{allowed}");
            assert!(target_ip_allowed(ip(allowed), true), "{allowed}");
        }
        for refused in [
            "169.254.169.254",
            "169.254.0.1",
            "100.100.100.200",
            "168.63.129.16",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "fe80::1",
            "::",
            "ff02::1",
            "fd00:ec2::254",
        ] {
            assert!(!target_ip_allowed(ip(refused), false), "{refused}");
            assert!(!target_ip_allowed(ip(refused), true), "{refused}");
        }
        for loopback in ["127.0.0.1", "127.255.255.254", "::1"] {
            assert!(!target_ip_allowed(ip(loopback), false), "{loopback}");
            assert!(target_ip_allowed(ip(loopback), true), "{loopback}");
        }
    }

    #[test]
    fn a_wrapped_ipv4_target_is_judged_as_its_plain_form() {
        // Every form parses to an IPv6 address, so none is the helper's fallback.
        for form in wrapped("10.0.0.1") {
            assert!(matches!(ip(&form), IpAddr::V6(_)), "{form}");
        }
        for never in ["169.254.169.254", "168.63.129.16", "100.100.100.200"] {
            for form in wrapped(never) {
                assert!(!target_ip_allowed(ip(&form), false), "{form}");
                assert!(!target_ip_allowed(ip(&form), true), "{form}");
            }
        }
        for form in wrapped("127.0.0.1") {
            assert!(!target_ip_allowed(ip(&form), false), "{form}");
            assert!(target_ip_allowed(ip(&form), true), "{form}");
        }
        for form in wrapped("10.0.0.1") {
            assert!(target_ip_allowed(ip(&form), false), "{form}");
            assert!(target_ip_allowed(ip(&form), true), "{form}");
        }
        // The forms named in the report, written out.
        for literal in [
            "::ffff:0:169.254.169.254",
            "::ffff:0:127.0.0.1",
            "2002:a9fe:a9fe::",
            "64:ff9b:1::a9fe:a9fe",
            "::ffff:168.63.129.16",
        ] {
            assert!(!target_ip_allowed(ip(literal), false), "{literal}");
        }
    }

    #[test]
    fn a_notice_goes_only_to_a_public_address() {
        for public in [
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.0.1",
            "172.32.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "2606:4700:4700::1111",
            "2a00:1450:4001::1",
            "2001:200::1",
            "2001:4860:4860::8888",
            "3ffe::1",
            "::ffff:1.1.1.1",
            "::ffff:0:1.1.1.1",
            "64:ff9b::101:101",
            "2002:0101:0101::1",
        ] {
            assert!(webhook_ip_allowed(ip(public), false), "{public}");
        }
        for refused in [
            // Loopback, unspecified, link-local and metadata.
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "169.254.169.254",
            "100.100.100.200",
            // RFC 1918 and carrier-grade NAT.
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            // Documentation, benchmark, protocol, reserved, multicast, broadcast.
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.0.1",
            "240.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            // IPv6: loopback, unspecified, link-local, unique-local,
            // site-local, multicast, documentation, metadata.
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "fd00:ec2::254",
            "100::1",
            // An IPv4 address inside an IPv6 one.
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:192.168.0.1",
            "::10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::a00:1",
            "2002:0a00:0001::1",
            "2002:7f00:0001::1",
            "2002:c0a8:0001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            // IPv4-translated ::ffff:0:a.b.c.d.
            "::ffff:0:127.0.0.1",
            "::ffff:0:7f00:1",
            "::ffff:0:169.254.169.254",
            "::ffff:0:a9fe:a9fe",
            "::ffff:0:10.0.0.1",
            // IPv6 that is not global unicast, or is set aside inside it.
            "fe00::1",
            "1::1",
            "::2",
            "::1:0:0:1",
            "::ffff",
            "64:ff9b:0:1::7f00:1",
            "2001:2::1",
            "2001:3::1",
            "2001:4:112::1",
            "2001:10::1",
            "2001:20::1",
            "2001:1ff:ffff::1",
            "3fff::1",
            "3fff:fff::1",
            "5f00::1",
            "4000::1",
            "e000::1",
            // Platform and relay addresses in public space.
            "168.63.129.16",
            "::ffff:168.63.129.16",
            "192.88.99.1",
            "2002:c058:6301::1",
        ] {
            assert!(!webhook_ip_allowed(ip(refused), false), "{refused}");
        }
    }

    #[test]
    fn local_development_lifts_only_the_private_ranges() {
        for local in ["127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "fd12::1"] {
            assert!(webhook_ip_allowed(ip(local), true), "{local}");
        }
        for never in [
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
            "fe80::1",
            "0.0.0.0",
            "224.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!webhook_ip_allowed(ip(never), true), "{never}");
        }
    }
}
