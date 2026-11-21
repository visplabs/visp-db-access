//! Rows that a query fetched and an answer could not hold, kept for the
//! agent's next calls.
//!
//! `run_query` fetches up to the policy's row cap and masks the rows; one
//! answer holds fewer. The rest stays here, in this node's memory only, so
//! that `fetch_rows` can hand it out without a second query. Nothing here
//! reaches the metadata database or a disk.
//!
//! Bounds: a held result ends five minutes after its last use; all held
//! results together, and those of one agent, stay under a byte cap (the
//! oldest go first); one agent holds at most [`MAX_PER_AGENT`] results. A
//! cursor is 32 random bytes; only its SHA-256 digest is the key here.
use crate::error::ApiError;
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vda_core::masking::Column;

/// How long held rows live after the query or the last page.
pub const IDLE: Duration = Duration::from_secs(300);
/// Held results of one agent at most; the oldest is dropped for a new one.
pub const MAX_PER_AGENT: usize = 32;
/// Marks a string as a cursor, so that anything else is refused unread.
const PREFIX: &str = "rows_";
const SECRET_BYTES: usize = 32;
/// Memory a JSON value takes beside its text, and a row beside its values.
const CELL_OVERHEAD: usize = 32;
const ROW_OVERHEAD: usize = 24;
/// A column beside its name and type: two strings and a flag.
const COLUMN_OVERHEAD: usize = 56;

/// The one answer for a cursor that names nothing this agent can read: a
/// cursor of another agent or token, an expired or used one, one that was
/// dropped, and one that lives on another node all look the same.
pub fn expired() -> ApiError {
    ApiError::new(
        StatusCode::GONE,
        "result_expired",
        "These rows are not held any more",
    )
}

/// The length of a row as JSON text, without building the text.
fn json_len(row: &[Value]) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    match serde_json::to_writer(&mut count, row) {
        Ok(()) => count.0,
        // A row that cannot be written cannot be sent either.
        Err(_) => usize::MAX,
    }
}
/// About how much memory a held row takes, from the length of its JSON text.
fn row_bytes(row: &[Value], json: usize) -> usize {
    json.saturating_add(row.len() * CELL_OVERHEAD)
        .saturating_add(ROW_OVERHEAD)
}

/// The rows of one query run that are still to be handed out, already
/// masked, and what binds them to the agent that ran it.
#[derive(Debug)]
pub struct Held {
    pub agent_id: Uuid,
    pub token_id: Uuid,
    /// The person the agent acts for.
    pub owner_id: Uuid,
    pub database: Uuid,
    /// The agent's `updated_at` when the query ran. A pause, a resume or a
    /// change of the agent moves it, on every node.
    pub agent_mark: DateTime<Utc>,
    /// The cluster's `updated_at` when the query ran. A change of its policy,
    /// masking, endpoint or agent login moves it, on every node.
    pub cluster_mark: DateTime<Utc>,
    pub query_id: Uuid,
    pub history_id: Option<Uuid>,
    pub columns: Vec<Column>,
    /// Whether the database had more rows than the policy lets one query fetch.
    pub truncated: bool,
    pub elapsed_ms: u64,
    rows: VecDeque<Vec<Value>>,
    /// About how much memory the rows take; counted when they are first held.
    bytes: usize,
    measured: bool,
}
impl Held {
    /// Take over the rows of a result.
    pub fn with_rows(mut self, rows: Vec<Vec<Value>>) -> Self {
        self.rows = rows.into();
        self.bytes = 0;
        self.measured = false;
        self
    }
    /// Count the size of what is held, once: the rows, and the columns that
    /// every page repeats. A result whose rows all fit in the first answer
    /// is never held, and so never counted.
    fn measure(&mut self) {
        if !self.measured {
            let columns = self.columns.iter().fold(0, |sum: usize, column| {
                sum.saturating_add(column.name.len() + column.type_name.len() + COLUMN_OVERHEAD)
            });
            self.bytes = self.rows.iter().fold(columns, |sum: usize, row| {
                sum.saturating_add(row_bytes(row, json_len(row)))
            });
            self.measured = true;
        }
    }
    /// The part that says where the rows came from; [`Held::with_rows`] adds
    /// the rows.
    #[allow(clippy::too_many_arguments)]
    pub fn of(
        agent_id: Uuid,
        token_id: Uuid,
        owner_id: Uuid,
        database: Uuid,
        agent_mark: DateTime<Utc>,
        cluster_mark: DateTime<Utc>,
        history_id: Option<Uuid>,
        result: &vda_core::query::QueryResult,
    ) -> Self {
        Self {
            agent_id,
            token_id,
            owner_id,
            database,
            agent_mark,
            cluster_mark,
            query_id: result.query_id,
            history_id,
            columns: result.columns.clone(),
            truncated: result.truncated,
            elapsed_ms: result.elapsed_ms,
            rows: VecDeque::new(),
            bytes: 0,
            measured: false,
        }
    }
    /// Rows still to be handed out.
    pub fn left(&self) -> usize {
        self.rows.len()
    }
    /// Take the next rows for one answer: at most `max_rows` rows and
    /// `max_bytes` of JSON text. When not even one row fits, an empty answer
    /// would look like no data, so that is an error.
    pub fn page(&mut self, max_rows: usize, max_bytes: usize) -> Result<Vec<Vec<Value>>, ApiError> {
        let mut page = Vec::new();
        let mut bytes = 0usize;
        while page.len() < max_rows {
            let Some(row) = self.rows.front() else {
                break;
            };
            let json = json_len(row);
            bytes = bytes.saturating_add(json);
            if bytes > max_bytes {
                break;
            }
            self.bytes = self.bytes.saturating_sub(row_bytes(row, json));
            if let Some(row) = self.rows.pop_front() {
                page.push(row);
            }
        }
        if page.is_empty() && !self.rows.is_empty() {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "result_too_large",
                "One row of this result is larger than a tool answer can hold",
            ));
        }
        Ok(page)
    }
}

type Key = [u8; 32];
struct Entry {
    held: Held,
    /// When it was put here: by the query, or by the last page.
    touched: Instant,
    /// Its place in the order of arrival; smaller is older.
    order: u64,
}
#[derive(Default)]
struct AgentUse {
    bytes: usize,
    /// The agent's entries, oldest first.
    keys: VecDeque<Key>,
}
#[derive(Default)]
struct Inner {
    entries: HashMap<Key, Entry>,
    /// Every entry by its order of arrival, oldest first.
    oldest: BTreeMap<u64, Key>,
    agents: HashMap<Uuid, AgentUse>,
    bytes: usize,
    arrivals: u64,
}
impl Inner {
    fn remove(&mut self, key: &Key, reason: &'static str) -> Option<Held> {
        let entry = self.entries.remove(key)?;
        self.oldest.remove(&entry.order);
        self.bytes = self.bytes.saturating_sub(entry.held.bytes);
        if let Some(usage) = self.agents.get_mut(&entry.held.agent_id) {
            usage.bytes = usage.bytes.saturating_sub(entry.held.bytes);
            usage.keys.retain(|held| held != key);
            if usage.keys.is_empty() {
                self.agents.remove(&entry.held.agent_id);
            }
        }
        if reason != "taken" {
            metrics::counter!("vda_held_results_dropped_total", "reason" => reason).increment(1);
        }
        Some(entry.held)
    }
    fn sweep(&mut self, now: Instant) -> usize {
        let gone: Vec<Key> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.saturating_duration_since(entry.touched) >= IDLE)
            .map(|(key, _)| *key)
            .collect();
        for key in &gone {
            self.remove(key, "expired");
        }
        gone.len()
    }
    fn gauges(&self) {
        metrics::gauge!("vda_held_results").set(self.entries.len() as f64);
        metrics::gauge!("vda_held_result_bytes").set(self.bytes as f64);
    }
}

/// The held results of this node.
pub struct HeldResults {
    inner: Mutex<Inner>,
    max_bytes: usize,
    max_agent_bytes: usize,
}
impl std::fmt::Debug for HeldResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the rows: they are query results.
        let (results, bytes) = self.usage();
        f.debug_struct("HeldResults")
            .field("results", &results)
            .field("bytes", &bytes)
            .finish()
    }
}
fn cursor_key(cursor: &str) -> Option<Key> {
    let body = cursor.strip_prefix(PREFIX)?;
    let decoded = URL_SAFE_NO_PAD.decode(body).ok()?;
    (decoded.len() == SECRET_BYTES).then(|| Sha256::digest(cursor.as_bytes()).into())
}
impl HeldResults {
    /// `max_bytes` bounds all held results of this node together, and
    /// `max_agent_bytes` those of one agent. Zero holds nothing.
    pub fn new(max_bytes: usize, max_agent_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            max_bytes,
            max_agent_bytes: max_agent_bytes.min(max_bytes),
        }
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // The map stays usable if a thread panicked while it held the lock.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Keep rows for the agent's next call and return the cursor that names
    /// them, or `None` when they cannot be kept: nothing is left, or the rows
    /// alone are larger than a cap. Older results make room: first the
    /// agent's own, then the oldest of anyone.
    pub fn hold(&self, mut held: Held, now: Instant) -> Option<String> {
        if held.rows.is_empty() || self.max_bytes == 0 {
            return None;
        }
        held.measure();
        if held.bytes > self.max_agent_bytes {
            metrics::counter!("vda_held_results_dropped_total", "reason" => "too_large")
                .increment(1);
            return None;
        }
        let mut secret = [0u8; SECRET_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let cursor = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(secret));
        let key: Key = Sha256::digest(cursor.as_bytes()).into();
        let mut inner = self.lock();
        inner.sweep(now);
        let agent = held.agent_id;
        loop {
            let usage = inner.agents.get(&agent);
            let (used, count) = usage.map_or((0, 0), |usage| (usage.bytes, usage.keys.len()));
            if used.saturating_add(held.bytes) <= self.max_agent_bytes && count < MAX_PER_AGENT {
                break;
            }
            let Some(oldest) = usage.and_then(|usage| usage.keys.front().copied()) else {
                break;
            };
            inner.remove(&oldest, "memory");
        }
        while inner.bytes.saturating_add(held.bytes) > self.max_bytes {
            let Some(oldest) = inner.oldest.values().next().copied() else {
                break;
            };
            inner.remove(&oldest, "memory");
        }
        inner.arrivals += 1;
        let order = inner.arrivals;
        inner.bytes = inner.bytes.saturating_add(held.bytes);
        let usage = inner.agents.entry(agent).or_default();
        usage.bytes = usage.bytes.saturating_add(held.bytes);
        usage.keys.push_back(key);
        inner.oldest.insert(order, key);
        inner.entries.insert(
            key,
            Entry {
                held,
                touched: now,
                order,
            },
        );
        inner.gauges();
        Some(cursor)
    }
    /// Take the rows a cursor names out of the store, when the cursor is
    /// this agent's and this token's and the rows are still alive. A cursor
    /// works once: the caller hands out a page and holds the rest again
    /// under a new cursor.
    pub fn take(&self, cursor: &str, agent: Uuid, token: Uuid, now: Instant) -> Option<Held> {
        let key = cursor_key(cursor)?;
        let mut inner = self.lock();
        let entry = inner.entries.get(&key)?;
        // Another agent's or token's cursor is left where it is: its owner
        // can still use it.
        if entry.held.agent_id != agent || entry.held.token_id != token {
            return None;
        }
        if now.saturating_duration_since(entry.touched) >= IDLE {
            inner.remove(&key, "expired");
            inner.gauges();
            return None;
        }
        let held = inner.remove(&key, "taken");
        inner.gauges();
        held
    }
    /// Drop every held result that matches, and count them. Used when an
    /// agent is paused, deleted or loses a token, and when a database's
    /// policy, masking or endpoint changes.
    pub fn drop_where(&self, reason: &'static str, matches: impl Fn(&Held) -> bool) -> usize {
        let mut inner = self.lock();
        let gone: Vec<Key> = inner
            .entries
            .iter()
            .filter(|(_, entry)| matches(&entry.held))
            .map(|(key, _)| *key)
            .collect();
        for key in &gone {
            inner.remove(key, reason);
        }
        inner.gauges();
        gone.len()
    }
    /// Drop what has not been used for [`IDLE`] at `now`, and count it.
    pub fn sweep(&self, now: Instant) -> usize {
        let mut inner = self.lock();
        let gone = inner.sweep(now);
        inner.gauges();
        gone
    }
    /// How many results are held, and about how many bytes they take.
    pub fn usage(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.entries.len(), inner.bytes)
    }
}

/// Free the memory of results nobody came back for. A cursor is also
/// checked when it is used, so this only bounds how long idle rows stay.
pub async fn sweeper(held: std::sync::Arc<HeldResults>, stop: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {_ = stop.cancelled() => break, _ = interval.tick() => {}}
        held.sweep(Instant::now());
    }
    // The gateway is stopping: nothing can ask for these rows any more.
    held.drop_where("stopped", |_| true);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use serde_json::json;

    fn held(agent: Uuid, token: Uuid, rows: usize, text: usize) -> Held {
        let rows = (0..rows)
            .map(|n| vec![json!(n), json!("x".repeat(text))])
            .collect();
        Held {
            agent_id: agent,
            token_id: token,
            owner_id: Uuid::nil(),
            database: Uuid::nil(),
            agent_mark: DateTime::<Utc>::MIN_UTC,
            cluster_mark: DateTime::<Utc>::MIN_UTC,
            query_id: Uuid::new_v4(),
            history_id: None,
            columns: vec![],
            truncated: false,
            elapsed_ms: 0,
            rows: VecDeque::new(),
            bytes: 0,
            measured: false,
        }
        .with_rows(rows)
    }

    #[test]
    fn a_cursor_works_once_for_its_agent_and_token_and_only_while_alive() {
        let store = HeldResults::new(1 << 20, 1 << 20);
        let (agent, token, now) = (Uuid::new_v4(), Uuid::new_v4(), Instant::now());
        assert_eq!(store.hold(held(agent, token, 0, 1), now), None);
        let cursor = store.hold(held(agent, token, 5, 10), now).unwrap();
        assert!(cursor.starts_with(PREFIX) && cursor.len() == PREFIX.len() + 43);
        // Garbage, another agent and another token get nothing and take nothing.
        let longer = format!("{cursor}x");
        for bad in ["", "rows_", "rows_!!!", "x", longer.as_str()] {
            assert!(store.take(bad, agent, token, now).is_none(), "{bad:?}");
        }
        assert!(store.take(&cursor, Uuid::new_v4(), token, now).is_none());
        assert!(store.take(&cursor, agent, Uuid::new_v4(), now).is_none());
        assert_eq!(store.usage().0, 1);
        let mut taken = store.take(&cursor, agent, token, now).unwrap();
        assert_eq!(taken.left(), 5);
        assert!(store.take(&cursor, agent, token, now).is_none(), "once");
        assert_eq!(store.usage(), (0, 0));
        // A page takes rows in order; the rest is held under a new cursor.
        let page = taken.page(2, 1 << 20).unwrap();
        assert_eq!(
            page.iter().map(|row| row[0].clone()).collect::<Vec<_>>(),
            [json!(0), json!(1)]
        );
        let next = store.hold(taken, now).unwrap();
        assert_ne!(next, cursor);
        // Alive until the idle time has passed, then gone.
        let late = now + IDLE - Duration::from_millis(1);
        let rest = store.take(&next, agent, token, late).unwrap();
        assert_eq!(rest.left(), 3);
        let again = store.hold(rest, now).unwrap();
        assert!(store.take(&again, agent, token, now + IDLE).is_none());
        assert_eq!(store.usage(), (0, 0));
        // The sweep frees what nobody came back for.
        store.hold(held(agent, token, 3, 10), now).unwrap();
        assert_eq!(store.sweep(now + IDLE - Duration::from_secs(1)), 0);
        assert_eq!(store.sweep(now + IDLE), 1);
        assert_eq!(store.usage(), (0, 0));
    }

    #[test]
    fn the_columns_of_a_held_result_count_toward_its_size() {
        let mut plain = held(Uuid::nil(), Uuid::nil(), 2, 10);
        plain.measure();
        let mut wide = held(Uuid::nil(), Uuid::nil(), 2, 10);
        wide.columns = (0..1000)
            .map(|n| Column {
                name: format!("a_long_column_name_{n}"),
                type_name: "text".into(),
                masked: false,
            })
            .collect();
        wide.measure();
        assert!(
            wide.bytes > plain.bytes + 1000 * COLUMN_OVERHEAD,
            "{}",
            wide.bytes
        );
        // A result with very many columns can be too large to hold.
        let store = HeldResults::new(plain.bytes + 1000, plain.bytes + 1000);
        assert!(store.hold(plain, Instant::now()).is_some());
        assert_eq!(store.hold(wide, Instant::now()), None);
    }

    #[test]
    fn a_page_obeys_the_row_and_byte_caps_and_never_comes_back_empty() {
        let mut result = held(Uuid::new_v4(), Uuid::new_v4(), 10, 100);
        result.measure();
        assert!(result.bytes > 0);
        let size = json_len(&result.rows[0]);
        // Three rows fit in the bytes; the row cap does not matter then.
        let page = result.page(100, size * 3 + 1).unwrap();
        assert_eq!(page.len(), 3);
        assert_eq!(result.page(2, usize::MAX).unwrap().len(), 2);
        // Not even one row fits: an error, and the rows stay.
        let error = result.page(100, size - 1).unwrap_err();
        assert_eq!(error.code, "result_too_large");
        assert_eq!(result.left(), 5);
        assert_eq!(result.page(100, usize::MAX).unwrap().len(), 5);
        assert_eq!(result.page(100, usize::MAX).unwrap().len(), 0);
        assert_eq!(result.bytes, 0);
    }

    #[test]
    fn the_caps_hold_and_the_oldest_results_make_room() {
        let mut sample = held(Uuid::nil(), Uuid::nil(), 10, 1000);
        sample.measure();
        let one = sample.bytes;
        let store = HeldResults::new(one * 5, one * 2);
        let (a, b, c, token, now) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Instant::now(),
        );
        // A result that is larger than the agent's cap is not held at all.
        assert_eq!(store.hold(held(a, token, 30, 1000), now), None);
        // The agent's third result drops its first.
        let first = store.hold(held(a, token, 10, 1000), now).unwrap();
        let second = store.hold(held(a, token, 10, 1000), now).unwrap();
        let third = store.hold(held(a, token, 10, 1000), now).unwrap();
        assert!(store.take(&first, a, token, now).is_none());
        assert_eq!(store.usage(), (2, one * 2));
        // Other agents fill the node; the oldest of anyone goes first.
        let other = store.hold(held(b, token, 10, 1000), now).unwrap();
        store.hold(held(b, token, 10, 1000), now).unwrap();
        store.hold(held(c, token, 10, 1000), now).unwrap();
        assert_eq!(store.usage(), (5, one * 5));
        store.hold(held(c, token, 10, 1000), now).unwrap();
        assert!(store.usage().1 <= one * 5);
        assert!(
            store.take(&second, a, token, now).is_none(),
            "the oldest went"
        );
        assert!(store.take(&third, a, token, now).is_some());
        assert!(store.take(&other, b, token, now).is_some());
        // An agent holds a bounded number of results, however small.
        let many: Vec<String> = (0..MAX_PER_AGENT + 3)
            .map(|_| store.hold(held(a, token, 1, 1), now).unwrap())
            .collect();
        let alive = many
            .iter()
            .filter(|cursor| store.take(cursor, a, token, now).is_some())
            .count();
        assert_eq!(alive, MAX_PER_AGENT);
        // Dropping by a rule takes exactly the matching results.
        store.hold(held(a, token, 1, 1), now).unwrap();
        let kept = store.hold(held(b, token, 1, 1), now).unwrap();
        assert!(store.drop_where("stopped", |held| held.agent_id == a) >= 1);
        assert!(store.take(&kept, b, token, now).is_some());
        // With a cap of zero nothing is held.
        assert_eq!(HeldResults::new(0, 0).hold(held(a, token, 1, 1), now), None);
    }
}
