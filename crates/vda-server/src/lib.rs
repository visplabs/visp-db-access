//! HTTP gateway, security primitives and metadata storage for visp-db-access.
mod access;
mod admin;
pub mod agents;
pub mod app;
pub mod approvals;
pub mod auth;
mod clusters;
pub mod config;
pub mod db;
pub mod discovery;
pub mod error;
pub mod health;
pub mod metrics;
pub mod network;
pub mod query;
pub mod rbac;
mod web;

// The pipeline modules live in `vda-core`; these paths stay for callers.
pub use vda_core::{audit, crypto, masking, policy, pools, sanitation};
