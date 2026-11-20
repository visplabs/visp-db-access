//! Notices to approvers.
//!
//! When a request for a write changes state, a notice is written to an outbox
//! in the same transaction. A worker on every node delivers the outbox to one
//! webhook. Nothing is sent inside a request handler, and a state change that
//! is rolled back leaves no notice.
//!
//! A notice says that something waits, not what it is: it never holds SQL,
//! rows, a preview or the text of a database error.
pub(crate) mod api;
pub mod format;
pub mod send;
pub mod worker;

use crate::{app::AppState, error::ApiError};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// The associated data of the encrypted webhook address and signing secret.
/// They are fixed, so a ciphertext moved from one field to the other, or
/// copied from a cluster's password, does not decrypt.
const URL_AAD: Uuid = Uuid::from_u128(0x6e6f_7469_6365_4000_8000_0000_0075_726c);
const SECRET_AAD: Uuid = Uuid::from_u128(0x6e6f_7469_6365_4000_8000_0073_6563_7265);

/// How many test notices one node sends in a minute, for everyone together.
pub const TESTS_PER_MINUTE: u32 = 5;
/// How long a reason may be in a notice, in characters.
pub const REASON_LIMIT: usize = 500;

/// A state change of a request that approvers can be told about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Created,
    Previewed,
    Approved,
    Rejected,
    Withdrawn,
    Executed,
    Failed,
    Expired,
}
impl Event {
    /// Every event, in the order the console lists them.
    pub const ALL: [Event; 8] = [
        Event::Created,
        Event::Previewed,
        Event::Approved,
        Event::Rejected,
        Event::Withdrawn,
        Event::Executed,
        Event::Failed,
        Event::Expired,
    ];
    /// The name on the wire and in the settings.
    pub fn name(self) -> &'static str {
        match self {
            Event::Created => "approval.created",
            Event::Previewed => "approval.previewed",
            Event::Approved => "approval.approved",
            Event::Rejected => "approval.rejected",
            Event::Withdrawn => "approval.withdrawn",
            Event::Executed => "approval.executed",
            Event::Failed => "approval.failed",
            Event::Expired => "approval.expired",
        }
    }
    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|event| event.name() == name)
    }
}

/// The shape of the request body that is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// The gateway's own JSON, signed.
    Webhook,
    /// A Slack incoming webhook.
    Slack,
}

/// What is stored under the `notices` key of `settings`. The address and the
/// secret are ciphertexts here; nothing in this value is a secret in clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
    pub format: Format,
    #[serde(default)]
    pub url_enc: Option<String>,
    /// The host of the address, shown to administrators in its place.
    #[serde(default)]
    pub url_host: Option<String>,
    #[serde(default)]
    pub secret_enc: Option<String>,
    pub events: Vec<String>,
    #[serde(default)]
    pub include_reason: bool,
    #[serde(default)]
    pub include_row_count: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            format: Format::Webhook,
            url_enc: None,
            url_host: None,
            secret_enc: None,
            events: vec![Event::Created.name().to_owned()],
            include_reason: false,
            include_row_count: false,
        }
    }
}
impl Settings {
    /// Whether a state change of this kind writes a notice.
    pub fn wants(&self, event: Event) -> bool {
        self.enabled && self.events.iter().any(|name| name == event.name())
    }
}

/// What a state change may say about its request. There is no field for SQL,
/// a preview, a result or an error text, so none of them can reach a notice.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Facts {
    pub status: String,
    pub cluster: String,
    pub environment: String,
    pub engine: String,
    pub requester: String,
    pub agent: Option<String>,
    pub reason: String,
    pub error_code: Option<String>,
    pub affected_rows: Option<i64>,
}
const FACTS_SQL: &str =
    "SELECT a.status,c.name AS cluster,c.environment,c.engine,u.name AS requester,
     a.agent_name AS agent,a.reason,a.error_code,
     CASE WHEN a.status='executed' THEN (a.result->>'affected_rows')::bigint
          ELSE (a.preview->>'affected_rows')::bigint END AS affected_rows
     FROM approvals a JOIN clusters c ON c.id=a.cluster_id JOIN users u ON u.id=a.requester_id
     WHERE a.id=$1";

/// The link to a request in the console, when the public address is known.
pub fn link(origin: Option<&str>, approval: Uuid) -> Option<String> {
    origin.map(|origin| format!("{origin}/approvals?id={approval}&tab=all"))
}
/// The neutral body of a notice. It is built when the state changes, with
/// the privacy switches of that moment, and stored; the worker later sends
/// it. A change of the settings that would make a stored body wrong (a
/// switch turned off, another address or format) removes the field from the
/// bodies that wait, or drops them: see `api::put`.
pub fn payload(
    event: Event,
    approval: Uuid,
    facts: &Facts,
    settings: &Settings,
    origin: Option<&str>,
    time: DateTime<Utc>,
) -> Value {
    let mut body = Map::new();
    body.insert("version".into(), json!(1));
    body.insert("event".into(), json!(event.name()));
    body.insert(
        "time".into(),
        json!(time.to_rfc3339_opts(SecondsFormat::Millis, true)),
    );
    body.insert("approval_id".into(), json!(approval));
    // Names and the reason come from people and agents. Each is made one
    // plain line of bounded length, in both formats.
    let name = |text: &str| format::plain(text, format::NAME_LIMIT);
    body.insert("status".into(), json!(facts.status));
    body.insert("cluster".into(), json!(name(&facts.cluster)));
    body.insert("environment".into(), json!(name(&facts.environment)));
    body.insert("engine".into(), json!(name(&facts.engine)));
    body.insert("requester".into(), json!(name(&facts.requester)));
    body.insert("agent".into(), json!(facts.agent.as_deref().map(name)));
    if let Some(url) = link(origin, approval) {
        body.insert("url".into(), json!(url));
    }
    if event == Event::Failed {
        body.insert("error_code".into(), json!(facts.error_code));
    }
    if settings.include_reason {
        body.insert(
            "reason".into(),
            json!(format::plain(&facts.reason, REASON_LIMIT)),
        );
    }
    if settings.include_row_count {
        if let Some(rows) = facts.affected_rows {
            body.insert("affected_rows".into(), json!(rows));
        }
    }
    Value::Object(body)
}
/// The body of the notice that "Send test" sends. It is about no request.
pub fn test_payload(origin: Option<&str>, time: DateTime<Utc>) -> Value {
    let mut body = Map::new();
    body.insert("version".into(), json!(1));
    body.insert("event".into(), json!(format::TEST_EVENT));
    body.insert(
        "time".into(),
        json!(time.to_rfc3339_opts(SecondsFormat::Millis, true)),
    );
    if let Some(origin) = origin {
        body.insert("url".into(), json!(origin));
    }
    Value::Object(body)
}

/// Write the notice of a state change into the outbox, on the transaction
/// that makes the change. Does nothing when notices are off or the event is
/// not selected.
///
/// The settings are read here, on the same transaction, and never from a
/// cache: a node that has not heard of a change yet must not miss the first
/// notice after notices are turned on, and must not put a reason or a row
/// count into a notice after its switch was turned off. When a notice will
/// be written, the settings row is read again with a shared lock. A change
/// of the settings takes the row exclusively, so it waits for this
/// transaction and then sees this notice when it cleans the outbox; a notice
/// can never be committed with the fields of settings that are already gone.
pub async fn enqueue(
    state: &AppState,
    tx: &mut sqlx::PgConnection,
    approval: Uuid,
    event: Event,
) -> Result<(), ApiError> {
    // Without a lock first: most installations have notices off, and those
    // should not write to the settings row for every state change.
    match load(&mut *tx, Lock::None).await? {
        Some(settings) if settings.wants(event) => {}
        _ => return Ok(()),
    }
    let Some(settings) = load(&mut *tx, Lock::Share).await? else {
        return Ok(());
    };
    if !settings.wants(event) {
        return Ok(());
    }
    let facts: Facts = sqlx::query_as(FACTS_SQL)
        .bind(approval)
        .fetch_one(&mut *tx)
        .await?;
    let body = payload(
        event,
        approval,
        &facts,
        &settings,
        state.config.public_origin().as_deref(),
        Utc::now(),
    );
    // A notice is due at once, unless an earlier one of its request waits for
    // a later attempt: then it could not be sent before that attempt anyway,
    // and it starts with that time so that the worker does not read it until
    // then (see `worker`). Only a time further away than a claim's lease
    // counts, by the clock and not by the start of this transaction: a
    // lease is not a wait, the notice it holds may be delivered in a moment.
    sqlx::query(
        "INSERT INTO notices(id,approval_id,event,payload,next_attempt_at) VALUES ($1,$2,$3,$4,
         GREATEST(now(),(SELECT max(next_attempt_at) FROM notices WHERE approval_id=$2
          AND status='pending' AND next_attempt_at>clock_timestamp()+make_interval(secs=>$5))))",
    )
    .bind(Uuid::new_v4())
    .bind(approval)
    .bind(event.name())
    .bind(body)
    .bind(f64::from(worker::LEASE_SECONDS))
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// How the settings row is held while it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lock {
    None,
    /// Held with others that write or send notices; excludes a change.
    Share,
    /// Held alone, by a change of the settings.
    Update,
}
/// Read the stored settings. `None` means that there is a value and this
/// version cannot read it (a newer version wrote it, or it is damaged). That
/// is "unknown", not "off": the caller writes and sends nothing, drops
/// nothing, and does not overwrite the value. An approval still changes
/// state. A missing row is the defaults.
pub(crate) async fn load(
    db: impl sqlx::PgExecutor<'_>,
    lock: Lock,
) -> Result<Option<Settings>, ApiError> {
    let sql = match lock {
        Lock::None => "SELECT value FROM settings WHERE key='notices'",
        Lock::Share => "SELECT value FROM settings WHERE key='notices' FOR SHARE",
        Lock::Update => "SELECT value FROM settings WHERE key='notices' FOR UPDATE",
    };
    let value: Option<Value> = sqlx::query_scalar(sql).fetch_optional(db).await?;
    Ok(match value.map(serde_json::from_value::<Settings>) {
        Some(Ok(settings)) => Some(settings),
        Some(Err(error)) => {
            unreadable_logged(&error);
            None
        }
        None => Some(Settings::default()),
    })
}
/// Say that the stored settings cannot be read, at most once a minute: the
/// worker would otherwise say it every few seconds.
fn unreadable_logged(error: &serde_json::Error) {
    use std::sync::atomic::{AtomicI64, Ordering};
    static LAST: AtomicI64 = AtomicI64::new(0);
    let now = Utc::now().timestamp();
    let last = LAST.load(Ordering::Relaxed);
    if now - last >= 60
        && LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::error!(
            %error,
            "the stored notice settings cannot be read by this version; no notice is written or sent until they can"
        );
    }
}
/// What the API answers while the stored settings cannot be read.
pub(crate) fn unreadable() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::CONFLICT,
        "settings_unreadable",
        "The notice settings were written by a newer version and cannot be read or changed by this one",
    )
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            status: "pending".into(),
            cluster: "orders".into(),
            environment: "production".into(),
            engine: "postgres".into(),
            requester: "Ada Admin".into(),
            agent: None,
            reason: "Fix the notes".into(),
            error_code: Some("effect_changed".into()),
            affected_rows: Some(3),
        }
    }
    fn on() -> Settings {
        Settings {
            enabled: true,
            ..Settings::default()
        }
    }
    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap_or_default()
    }

    #[test]
    fn the_time_has_milliseconds_and_names_are_one_plain_line() {
        let when = DateTime::from_timestamp(1_800_000_000, 123_456_789).unwrap_or_default();
        let mut hostile = facts();
        hostile.cluster = "orders\nApproved by Security".into();
        hostile.requester = "Ada\u{202e}nimdA".into();
        hostile.agent = Some("bot\u{0}\tname".into());
        hostile.reason = "line one\r\nline two".into();
        let mut settings = on();
        settings.include_reason = true;
        let body = payload(Event::Created, Uuid::nil(), &hostile, &settings, None, when);
        assert_eq!(body["time"], "2027-01-15T08:00:00.123Z");
        assert_eq!(body["cluster"], "orders Approved by Security");
        assert_eq!(body["requester"], "AdanimdA");
        assert_eq!(body["agent"], "bot name");
        assert_eq!(body["reason"], "line one line two");
        hostile.requester = "n".repeat(500);
        let body = payload(Event::Created, Uuid::nil(), &hostile, &settings, None, when);
        assert_eq!(
            body["requester"].as_str().map(|name| name.chars().count()),
            Some(format::NAME_LIMIT)
        );
    }
    fn keys(value: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .map(|object| object.keys().map(String::as_str).collect())
            .unwrap_or_default();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn a_notice_holds_only_the_listed_fields() {
        let id = Uuid::from_u128(7);
        let body = payload(Event::Created, id, &facts(), &on(), None, at());
        assert_eq!(
            keys(&body),
            [
                "agent",
                "approval_id",
                "cluster",
                "engine",
                "environment",
                "event",
                "requester",
                "status",
                "time",
                "version"
            ]
        );
        assert_eq!(body["version"], 1);
        assert_eq!(body["event"], "approval.created");
        assert_eq!(body["time"], "2027-01-15T08:00:00.000Z");
        assert_eq!(body["approval_id"], json!(id));
        assert_eq!(body["agent"], Value::Null);
        // No reason, no count and no error code unless they are asked for.
        let text = body.to_string();
        assert!(!text.contains("Fix the notes") && !text.contains("effect_changed"));
        assert!(body.get("affected_rows").is_none() && body.get("url").is_none());
    }

    #[test]
    fn each_switch_adds_exactly_its_own_field() {
        let id = Uuid::from_u128(7);
        let mut settings = on();
        settings.include_reason = true;
        let body = payload(Event::Created, id, &facts(), &settings, None, at());
        assert_eq!(body["reason"], "Fix the notes");
        assert!(body.get("affected_rows").is_none());
        settings.include_reason = false;
        settings.include_row_count = true;
        let body = payload(Event::Created, id, &facts(), &settings, None, at());
        assert_eq!(body["affected_rows"], 3);
        assert!(body.get("reason").is_none());
        // An unknown count is left out, not sent as zero.
        let mut unknown = facts();
        unknown.affected_rows = None;
        let body = payload(Event::Created, id, &unknown, &settings, None, at());
        assert!(body.get("affected_rows").is_none());
    }

    #[test]
    fn a_failure_carries_its_code_and_an_agent_its_name() {
        let id = Uuid::from_u128(7);
        let mut asked = facts();
        asked.agent = Some("billing-bot".into());
        asked.status = "failed".into();
        let body = payload(Event::Failed, id, &asked, &on(), None, at());
        assert_eq!(body["error_code"], "effect_changed");
        assert_eq!(body["agent"], "billing-bot");
        for other in Event::ALL.into_iter().filter(|e| *e != Event::Failed) {
            let body = payload(other, id, &asked, &on(), None, at());
            assert!(body.get("error_code").is_none(), "{}", other.name());
        }
    }

    #[test]
    fn a_long_reason_is_cut_on_a_character_boundary() {
        let mut settings = on();
        settings.include_reason = true;
        let mut long = facts();
        long.reason = "é".repeat(REASON_LIMIT + 200);
        let body = payload(Event::Created, Uuid::nil(), &long, &settings, None, at());
        let reason = body["reason"].as_str().unwrap_or_default();
        assert_eq!(reason.chars().count(), REASON_LIMIT);
        assert!(reason.ends_with('…'));
        long.reason = "é".repeat(REASON_LIMIT);
        let body = payload(Event::Created, Uuid::nil(), &long, &settings, None, at());
        assert_eq!(body["reason"], json!(long.reason));
    }

    #[test]
    fn a_link_is_added_only_with_a_public_address() {
        let id = Uuid::from_u128(7);
        let body = payload(
            Event::Created,
            id,
            &facts(),
            &on(),
            Some("https://gate.example"),
            at(),
        );
        assert_eq!(
            body["url"],
            format!("https://gate.example/approvals?id={id}&tab=all")
        );
        assert_eq!(link(None, id), None);
    }

    #[test]
    fn only_selected_events_are_wanted_and_only_when_on() {
        let mut settings = Settings::default();
        assert!(!settings.wants(Event::Created));
        settings.enabled = true;
        assert!(settings.wants(Event::Created));
        assert!(!settings.wants(Event::Executed));
        settings.events = Event::ALL.iter().map(|e| e.name().to_owned()).collect();
        assert!(Event::ALL.into_iter().all(|event| settings.wants(event)));
        for event in Event::ALL {
            assert_eq!(Event::parse(event.name()), Some(event));
        }
        assert_eq!(Event::parse("approval.execute"), None);
    }

    #[test]
    fn stored_settings_from_another_version_still_load() {
        let stored = json!({"enabled":true,"format":"slack","events":["approval.created"],
            "added_later":1});
        let settings: Settings = serde_json::from_value(stored).unwrap_or_default();
        assert!(settings.enabled && settings.format == Format::Slack);
        assert!(!settings.include_reason && settings.url_enc.is_none());
    }

    #[test]
    fn the_two_ciphertexts_cannot_be_swapped() {
        assert_ne!(URL_AAD, SECRET_AAD);
        let crypto = crate::crypto::Crypto::new(&[9; 32]);
        let url = crypto
            .encrypt(URL_AAD, "https://hooks.example/x")
            .unwrap_or_default();
        assert!(crypto.decrypt(SECRET_AAD, &url).is_err());
        assert!(crypto.decrypt(URL_AAD, &url).is_ok());
    }
}
