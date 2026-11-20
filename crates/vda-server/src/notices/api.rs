//! The settings of notices: read them, change them, make a new signing
//! secret, send a test. Organization administrators only.
//!
//! The webhook address is write-only: a response says that one is set and
//! names its host. The signing secret is made here, shown once in the
//! response that makes it, and never again. Neither is written to the audit
//! log or to a log line.
use super::{send::Target, worker, Event, Format, Lock, Settings, SECRET_AAD, URL_AAD};
use crate::{
    app::AppState,
    auth::User,
    error::{ApiError, Input},
    network::ClientIp,
    rbac,
};
use axum::{extract::State, Extension, Json};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

/// What a signing secret starts with, so a scanner can recognize one.
pub const SECRET_PREFIX: &str = "vda_whsec_";

/// The body of `PUT /settings/notices`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Update {
    enabled: bool,
    format: Format,
    /// Left out or null keeps the stored address; an empty string removes it.
    #[serde(default)]
    url: Option<SecretString>,
    events: Vec<String>,
    include_reason: bool,
    include_row_count: bool,
}

/// The settings as an administrator may see them, with the delivery status.
async fn view(state: &AppState, settings: &Settings) -> Result<Value, ApiError> {
    // Each part reads one small partial index: what waits, what was given
    // up, the newest delivery, the newest failure. The page asks for this
    // every few seconds, and the outbox keeps a month of rows.
    type Counts = (i64, i64, Option<chrono::DateTime<chrono::Utc>>);
    let (pending, dead, last_success_at): Counts = sqlx::query_as(
        "SELECT (SELECT count(*) FROM notices WHERE status='pending'),
                (SELECT count(*) FROM notices WHERE status='dead'),
                (SELECT max(sent_at) FROM notices WHERE status='sent')",
    )
    .fetch_one(&state.db)
    .await?;
    type Failed = (String, Option<chrono::DateTime<chrono::Utc>>);
    let failed: Option<Failed> = sqlx::query_as(
        "SELECT last_error,last_attempt_at FROM notices WHERE last_error IS NOT NULL
         ORDER BY last_attempt_at DESC LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await?;
    Ok(json!({
        "enabled": settings.enabled,
        "format": settings.format,
        "url_set": settings.url_enc.is_some(),
        "url_host": settings.url_host,
        "secret_set": settings.secret_enc.is_some(),
        "events": settings.events,
        "include_reason": settings.include_reason,
        "include_row_count": settings.include_row_count,
        // Whether a notice can link to the request (VDA_PUBLIC_URL is set).
        "links": state.config.public_origin().is_some(),
        "delivery": {
            "pending": pending,
            "dead": dead,
            "last_success_at": last_success_at,
            "last_error": failed.as_ref().map(|(class, _)| class),
            "last_error_at": failed.as_ref().and_then(|(_, at)| *at),
        },
    }))
}
/// Read the stored settings and hold their row alone until the transaction
/// ends. A change of the settings and a new secret cannot overwrite each
/// other, and nothing writes or claims a notice while the change cleans the
/// outbox. Settings that this version cannot read are not changed: 409.
async fn locked(tx: &mut sqlx::PgConnection) -> Result<Settings, ApiError> {
    super::load(&mut *tx, Lock::Update)
        .await?
        .ok_or_else(super::unreadable)
}
/// The settings for a request that only reads them.
async fn current(state: &AppState) -> Result<Settings, ApiError> {
    super::load(&state.db, Lock::None)
        .await?
        .ok_or_else(super::unreadable)
}
/// Mark the notices that wait as given up, for `reason`; with `events`, only
/// those of the events named. Returns how many.
async fn drop_waiting(
    tx: &mut sqlx::PgConnection,
    reason: &str,
    events: Option<&[String]>,
) -> Result<u64, ApiError> {
    let dropped = sqlx::query(
        "UPDATE notices SET status='dead',last_error=$1,last_attempt_at=now()
         WHERE status='pending' AND ($2::text[] IS NULL OR event=ANY($2))",
    )
    .bind(reason)
    .bind(events)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    metrics::counter!("vda_notices_dead_total").increment(dropped);
    Ok(dropped)
}
/// Make the outbox agree with a change of the settings, in the transaction
/// of that change. A notice that waits was built for the settings of its
/// moment: for one receiver, one format, the events selected then and the
/// private fields allowed then. What no longer holds must not be sent.
/// Returns how many waiting notices were dropped.
async fn clean_outbox(
    tx: &mut sqlx::PgConnection,
    before: &Settings,
    after: &Settings,
    address_changed: bool,
) -> Result<u64, ApiError> {
    // Everything that waits goes when its receiver or its shape is gone.
    let all = if !after.enabled {
        Some(worker::TURNED_OFF)
    } else if address_changed {
        Some(worker::ADDRESS_CHANGED)
    } else if before.format != after.format {
        Some(worker::FORMAT_CHANGED)
    } else {
        None
    };
    if let Some(reason) = all {
        return drop_waiting(tx, reason, None).await;
    }
    let deselected: Vec<String> = before
        .events
        .iter()
        .filter(|event| !after.events.contains(event))
        .cloned()
        .collect();
    let dropped = if deselected.is_empty() {
        0
    } else {
        let dropped = drop_waiting(tx, worker::EVENT_OFF, Some(&deselected)).await?;
        // A notice behind one that was just dropped may hold the time of
        // that one's next attempt (see `worker`); nothing is before it now,
        // so it is due. It cannot be on the wire: until this transaction an
        // earlier notice of its request still waited.
        sqlx::query(
            "UPDATE notices f SET next_attempt_at=now() WHERE f.status='pending'
             AND f.next_attempt_at>now() AND EXISTS(SELECT 1 FROM notices d
              WHERE d.approval_id=f.approval_id AND d.seq<f.seq AND d.status='dead'
              AND d.last_error=$1 AND d.last_attempt_at=now())",
        )
        .bind(worker::EVENT_OFF)
        .execute(&mut *tx)
        .await?;
        dropped
    };
    // A private field that was switched off leaves the bodies that wait.
    for (was, is, field) in [
        (before.include_reason, after.include_reason, "reason"),
        (
            before.include_row_count,
            after.include_row_count,
            "affected_rows",
        ),
    ] {
        if was && !is {
            sqlx::query("UPDATE notices SET payload=payload-$1 WHERE status='pending'")
                .bind(field)
                .execute(&mut *tx)
                .await?;
        }
    }
    Ok(dropped)
}
async fn store(tx: &mut sqlx::PgConnection, settings: &Settings) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO settings(key,value) VALUES ('notices',$1)
         ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
    )
    .bind(json!(settings))
    .execute(&mut *tx)
    .await?;
    Ok(())
}
/// The selected events, each once, in the order they are listed.
fn selected(names: &[String]) -> Result<Vec<String>, ApiError> {
    if names.iter().any(|name| Event::parse(name).is_none()) {
        return Err(ApiError::validation("Unknown notice event"));
    }
    Ok(Event::ALL
        .into_iter()
        .map(Event::name)
        .filter(|name| names.iter().any(|chosen| chosen == name))
        .map(str::to_owned)
        .collect())
}

/// The notice settings and the delivery status.
pub(crate) async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Json<Value>, ApiError> {
    rbac::require_admin(&user)?;
    let settings = current(&state).await?;
    Ok(Json(view(&state, &settings).await?))
}
/// Change the notice settings. They apply to notices written from now on,
/// and the notices that still wait are made to agree with them: see
/// [`clean_outbox`].
pub(crate) async fn put(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
    Input(body): Input<Update>,
) -> Result<Json<Value>, ApiError> {
    rbac::require_admin(&user)?;
    let events = selected(&body.events)?;
    let mut tx = state.db.begin().await?;
    let mut settings = locked(&mut tx).await?;
    let before = settings.clone();
    // The address that is stored now, to tell a new one from the same one
    // typed again. One that cannot be decrypted counts as another.
    let stored = before
        .url_enc
        .as_deref()
        .and_then(|stored| state.core.crypto.decrypt(URL_AAD, stored).ok());
    let url_changed = match body.url.as_ref().map(|url| url.expose_secret()) {
        None => false,
        Some("") => {
            settings.url_enc = None;
            settings.url_host = None;
            before.url_enc.is_some()
        }
        Some(raw) if stored.as_deref() == Some(raw) => false,
        Some(raw) => {
            let target = Target::parse(raw, state.config.allow_private_targets)
                .map_err(ApiError::validation)?;
            settings.url_enc = Some(
                state
                    .core
                    .crypto
                    .encrypt(URL_AAD, raw)
                    .map_err(|_| ApiError::internal())?,
            );
            settings.url_host = Some(target.host());
            true
        }
    };
    settings.enabled = body.enabled;
    settings.format = body.format;
    settings.events = events;
    settings.include_reason = body.include_reason;
    settings.include_row_count = body.include_row_count;
    if settings.enabled {
        if settings.url_enc.is_none() {
            return Err(ApiError::validation(
                "Set the webhook address before you turn notices on",
            ));
        }
        if settings.events.is_empty() {
            return Err(ApiError::validation("Select at least one event"));
        }
        // An unsigned webhook could not be told from a forged one.
        if settings.format == Format::Webhook && settings.secret_enc.is_none() {
            return Err(ApiError::validation(
                "Create the signing secret before you turn webhook notices on",
            ));
        }
    }
    store(&mut tx, &settings).await?;
    let dropped = clean_outbox(&mut tx, &before, &settings, url_changed).await?;
    state
        .audit_details(
            &mut tx,
            &user,
            "settings.notices",
            None,
            ip.0,
            json!({
                "enabled": settings.enabled,
                "format": settings.format,
                "events": settings.events,
                "include_reason": settings.include_reason,
                "include_row_count": settings.include_row_count,
                "url_changed": url_changed,
                "url_host": settings.url_host,
                "dropped_notices": dropped,
            }),
        )
        .await?;
    tx.commit().await?;
    Ok(Json(view(&state, &settings).await?))
}
/// Make a new signing secret and return it, once. A secret that was set
/// before stops working at once; queued notices are signed with the new one.
pub(crate) async fn rotate_secret(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
) -> Result<Json<Value>, ApiError> {
    use base64::Engine;
    use rand::RngCore;
    rbac::require_admin(&user)?;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let secret = format!(
        "{SECRET_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let mut tx = state.db.begin().await?;
    let mut settings = locked(&mut tx).await?;
    let rotated = settings.secret_enc.is_some();
    settings.secret_enc = Some(
        state
            .core
            .crypto
            .encrypt(SECRET_AAD, &secret)
            .map_err(|_| ApiError::internal())?,
    );
    store(&mut tx, &settings).await?;
    state
        .audit_details(
            &mut tx,
            &user,
            "settings.notices.secret",
            None,
            ip.0,
            json!({"rotated": rotated}),
        )
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"secret": secret, "rotated": rotated})))
}
/// Send a test notice now, to the stored address in the stored format, and
/// say how it went: the status code, or the class of the failure. Never a
/// part of the response. At most [`super::TESTS_PER_MINUTE`] a minute on a
/// node, for all administrators together.
pub(crate) async fn test(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Extension(ip): Extension<ClientIp>,
) -> Result<Json<Value>, ApiError> {
    rbac::require_admin(&user)?;
    let settings = current(&state).await?;
    if settings.url_enc.is_none() {
        return Err(ApiError::validation("Set the webhook address first"));
    }
    if settings.format == Format::Webhook && settings.secret_enc.is_none() {
        return Err(ApiError::validation("Create the signing secret first"));
    }
    // Counted once the stored settings allow a test, before anything is
    // sent: a call refused above for a missing address or secret is free, a
    // call whose stored address cannot be used still counts.
    state.check_notice_test_rate().await?;
    let payload = super::test_payload(state.config.public_origin().as_deref(), chrono::Utc::now());
    let outcome = match worker::route(&state, &settings) {
        Ok(route) => worker::send(&state.notices, &route, Uuid::new_v4(), None, &payload).await,
        Err(failure) => Err(failure),
    };
    let result = match outcome {
        Ok(status) => json!({"delivered": true, "status": status, "error": null}),
        Err(failure) => json!({
            "delivered": false,
            "status": failure.status(),
            "error": failure.class(),
        }),
    };
    let mut tx = state.db.begin().await?;
    state
        .audit_details(
            &mut tx,
            &user,
            "settings.notices.test",
            None,
            ip.0,
            result.clone(),
        )
        .await?;
    tx.commit().await?;
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_checked_deduplicated_and_ordered() {
        let chosen = [
            "approval.expired".to_owned(),
            "approval.created".to_owned(),
            "approval.expired".to_owned(),
        ];
        assert_eq!(
            selected(&chosen).ok(),
            Some(vec![
                "approval.created".to_owned(),
                "approval.expired".to_owned()
            ])
        );
        assert_eq!(selected(&[]).ok(), Some(Vec::new()));
        assert!(selected(&["approval.execute".to_owned()]).is_err());
        assert!(selected(&["notice.test".to_owned()]).is_err());
    }

    #[test]
    fn an_update_does_not_print_the_address() {
        let update: Result<Update, _> = serde_json::from_value(json!({
            "enabled": true, "format": "slack", "url": "https://hooks.example/T0/B0/token",
            "events": ["approval.created"], "include_reason": false, "include_row_count": false,
        }));
        let printed = format!("{update:?}");
        assert!(printed.starts_with("Ok("), "{printed}");
        assert!(!printed.contains("hooks.example") && !printed.contains("token"));
        // Unknown fields are refused, so a typo cannot silently do nothing.
        let unknown: Result<Update, _> = serde_json::from_value(json!({
            "enabled": true, "format": "slack", "events": [], "include_reason": false,
            "include_row_count": false, "secret": "x",
        }));
        assert!(unknown.is_err());
    }
}
