//! The API error envelope and the JSON body extractor that uses it.
use axum::Json;
use serde_json::Value;
pub use vda_core::error::{ApiError, ErrorKind};

/// JSON extractor with the API error envelope for malformed input.
#[derive(Debug)]
pub struct Input<T>(pub T);
impl<S, T> axum::extract::FromRequest<S> for Input<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = ApiError;
    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<Value>::from_request(req, state)
            .await
            .map_err(|_| ApiError::validation("Invalid JSON body"))?;
        crate::sanitation::json(&value)?;
        serde_json::from_value(value)
            .map(Self)
            .map_err(|_| ApiError::validation("Invalid JSON body"))
    }
}
