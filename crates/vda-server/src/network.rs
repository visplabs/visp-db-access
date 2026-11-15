//! Client network attribution, allowlists and target-address validation.
use crate::{app::AppState, error::ApiError};
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
pub use vda_core::network::{allowed, parse_cidrs, target_ip_allowed, validate_host};

/// Organization-level network settings persisted in the metadata store.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkSettings {
    pub allowed_cidrs: Vec<String>,
    pub trust_proxy_headers: bool,
}
/// Effective request IP set by the network gate.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);
/// Walk X-Forwarded-For from the trusted socket toward the rightmost untrusted hop.
pub fn client_ip(
    peer: IpAddr,
    forwarded: Option<&str>,
    trust: bool,
    proxies: &[IpNet],
) -> Result<IpAddr, ApiError> {
    // Fail closed: with no configured trusted proxies only the direct peer is trusted.
    if !trust || !proxies.iter().any(|n| n.contains(&peer)) {
        return Ok(peer);
    }
    let Some(value) = forwarded else {
        return Ok(peer);
    };
    if value.len() > 4096 {
        return Err(ApiError::validation("Invalid forwarded IP chain"));
    }
    let hops: Vec<IpAddr> = value
        .split(',')
        .map(|s| {
            s.trim()
                .parse()
                .map_err(|_| ApiError::validation("Invalid forwarded IP chain"))
        })
        .collect::<Result<_, _>>()?;
    for hop in hops.into_iter().rev() {
        if !proxies.iter().any(|n| n.contains(&hop)) {
            return Ok(hop);
        }
    }
    Ok(peer)
}
/// Apply runtime and immutable environment allowlists before authentication.
pub async fn gate(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let result = async {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|v| v.0.ip())
            .ok_or_else(ApiError::forbidden)?;
        let settings = state.network_settings().await?;
        let trust = state.config.trust_proxy_headers || settings.trust_proxy_headers;
        let forwarded = if trust {
            forwarded_chain(req.headers())?
        } else {
            None
        };
        let ip = client_ip(
            peer,
            forwarded.as_deref(),
            trust,
            &state.config.trusted_proxy_cidrs,
        )?;
        if !allowed(ip, &state.config.allowed_cidrs)
            || !allowed(ip, &parse_cidrs(&settings.allowed_cidrs)?)
        {
            return Err(ApiError::forbidden());
        }
        req.extensions_mut().insert(ClientIp(ip));
        Ok::<_, ApiError>(())
    }
    .await;
    match result {
        Ok(()) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}

/// Join all XFF header lines in wire order; reject malformed UTF-8 and oversized chains.
pub fn forwarded_chain(headers: &axum::http::HeaderMap) -> Result<Option<String>, ApiError> {
    let mut chain = String::new();
    for value in headers.get_all("x-forwarded-for") {
        if !chain.is_empty() {
            chain.push(',');
        }
        chain.push_str(
            value
                .to_str()
                .map_err(|_| ApiError::validation("Invalid forwarded IP chain"))?,
        );
        if chain.len() > 4096 {
            return Err(ApiError::validation("Invalid forwarded IP chain"));
        }
    }
    Ok(if chain.is_empty() { None } else { Some(chain) })
}

/// Enforce a cluster network policy on every target operation, including cached schema access.
pub async fn require_cluster(state: &AppState, id: uuid::Uuid, ip: IpAddr) -> Result<(), ApiError> {
    let policy = crate::db::policy(&state.db, id).await?;
    if !allowed(ip, &parse_cidrs(&policy.allowed_cidrs)?) {
        return Err(ApiError::forbidden());
    }
    Ok(())
}
