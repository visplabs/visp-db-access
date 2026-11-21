//! HTTP gateway, security primitives and metadata storage for visp-db-access.
mod access;
mod admin;
mod agent_login;
pub mod agents;
pub mod app;
pub mod approvals;
pub mod audit_chain;
pub mod auth;
mod clusters;
pub mod config;
pub mod db;
pub mod discovery;
pub mod error;
pub mod health;
pub mod held;
mod mcp;
pub mod metrics;
pub mod network;
pub mod notices;
pub mod query;
pub mod rbac;
pub mod steps;
mod web;

// The pipeline modules live in `vda-core`; these paths stay for callers.
pub use vda_core::{audit, chain, crypto, masking, policy, pools, sanitation};
