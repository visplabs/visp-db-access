//! The audit hash chain: what makes the audit log tamper-evident.
//!
//! Audit rows are written as before, from many connections and nodes at
//! once, with no lock. A sealer then appends one link per row to
//! `audit_chain`, in one total order, and each link carries a keyed hash of
//! the row and of the link before it. Whoever changes, deletes or reorders a
//! sealed row, or a link, without the master key leaves a chain that no
//! longer verifies.
//!
//! # The order
//!
//! Rows are sealed in the order `(txid, seq)`: the ID of the transaction
//! that inserted the row, then a sequence number. A row may be sealed only
//! when no transaction that is still running could commit a row that sorts
//! before it. PostgreSQL gives transaction IDs in rising order, and
//! `pg_snapshot_xmin` of a snapshot is the lowest ID that was still running
//! when the snapshot was taken: every lower ID has ended, and its rows, if
//! it committed, are visible in that snapshot. A transaction that has not
//! taken an ID yet will get a higher one. So the rows with
//! `txid < pg_snapshot_xmin(pg_current_snapshot())`, read in the statement
//! that owns the snapshot, are a set that can never get a new member, and
//! sealing them in `(txid, seq)` order never has to go back.
//!
//! The price is a delay: a transaction that stays open, in any database of
//! the same PostgreSQL instance, holds sealing back for every row written
//! after it began. The delay is measured and exported, not hidden.
//!
//! # The bytes
//!
//! ```text
//! row  = "vda-audit-row-v1" || field(id) || field(actor_id) || field(action)
//!        || field(target_type) || field(target_id) || field(ip)
//!        || field(details) || field(created_at) || field(seq) || field(txid)
//! field(NULL)  = 0x00
//! field(value) = 0x01 || u32be(len(value)) || value
//! hash = HMAC-SHA256(chain key, "vda-audit-link-v1" || u64be(position)
//!                    || u64be(segment_start) || prev_hash (32 bytes) || row)
//! ```
//!
//! The values are text, in UTF-8; [`Row`] says which text. The first link's
//! `prev_hash` is 32 zero bytes, every other link's is the hash of the link
//! before it, whichever key made that one.
//!
//! # Segments
//!
//! A link names the key that made it (`key_id`), and that name is only a
//! label: nothing stops someone with the database from writing another name
//! there, and a link of another key cannot be verified. So every link also
//! says, inside its hash, where the unbroken run of links of its key began
//! (`segment_start`). A link that verifies and follows a link of its own
//! key must name the same start as that link; one that follows a link of
//! another key, or no link, must name itself. A run cannot be given a hole
//! or a new beginning by relabelling: the first link after the relabelled
//! ones still names the old start, under a hash that cannot be made again.
//! Relabelling every link of the current key up to the head leaves no such
//! link; that, like cutting the end off, shows only against a checkpoint
//! kept outside the database.
use crate::crypto::Crypto;
use serde::Serialize;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// Starts the encoding of a row; a new encoding gets a new label.
pub const ROW_LABEL: &[u8] = b"vda-audit-row-v1";
/// Starts the input of a link's hash.
pub const LINK_LABEL: &[u8] = b"vda-audit-link-v1";
/// The `prev_hash` of the first link.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Only one session at a time appends to the chain.
pub const SEAL_LOCK: i32 = 762_104_223;
/// Only one session at a time runs the background check.
pub const VERIFY_LOCK: i32 = 762_104_224;
/// Take a lock for this transaction, or say that another session has it.
/// The lock is for the chain in the current schema: two installations in
/// one database, each in its own schema, do not wait for each other.
async fn try_lock(connection: &mut PgConnection, lock: i32) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1,hashtext(current_schema()))")
        .bind(lock)
        .fetch_one(connection)
        .await
}
/// Links read at once while checking.
const PAGE: i64 = 1000;
/// Objects and arrays may be nested this deep in `details` before the text
/// is hashed as stored instead of in canonical form.
const MAX_DEPTH: usize = 128;

/// The audit columns as they are hashed, read with [`ROW_COLUMNS`].
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Row {
    /// Lower-case, with hyphens, as are the other IDs.
    pub id: Uuid,
    pub actor_id: Option<Uuid>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    /// `text(ip)`: the address and the length of its mask, `10.1.2.3/32`.
    pub ip: Option<String>,
    /// `details::text`, put into canonical form by [`canonical_json`].
    pub details: String,
    /// Microseconds since 1970-01-01 UTC as a decimal number, which is the
    /// precision the column stores; `infinity` or `-infinity` otherwise.
    pub created_at: String,
    pub seq: i64,
    /// The transaction ID as a decimal number.
    pub txid: String,
}
/// The columns of [`Row`], for a query that names `audit_log` as `a`.
pub const ROW_COLUMNS: &str = "a.id,a.actor_id,a.action,a.target_type,a.target_id,text(a.ip) AS ip,
    a.details::text AS details,
    CASE WHEN isfinite(a.created_at)
         THEN round(extract(epoch FROM a.created_at)::numeric*1000000)::text
         ELSE a.created_at::text END AS created_at,
    a.seq,a.txid::text AS txid";

/// JSON text that this module cannot put into canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not canonical JSON input")]
pub struct Malformed;

struct Json<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Json<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }
    fn expect(&mut self, text: &[u8]) -> Result<(), Malformed> {
        for byte in text {
            if self.next() != Some(*byte) {
                return Err(Malformed);
            }
        }
        Ok(())
    }
    fn value(&mut self, depth: usize, out: &mut String) -> Result<(), Malformed> {
        if depth > MAX_DEPTH {
            return Err(Malformed);
        }
        self.space();
        match self.peek().ok_or(Malformed)? {
            b'{' => self.object(depth, out),
            b'[' => self.array(depth, out),
            b'"' => {
                let text = self.string()?;
                write_string(&text, out);
                Ok(())
            }
            b't' => self.expect(b"true").map(|()| out.push_str("true")),
            b'f' => self.expect(b"false").map(|()| out.push_str("false")),
            b'n' => self.expect(b"null").map(|()| out.push_str("null")),
            _ => self.number(out),
        }
    }
    fn object(&mut self, depth: usize, out: &mut String) -> Result<(), Malformed> {
        self.at += 1;
        let mut members: Vec<(String, String)> = Vec::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.at += 1;
        } else {
            loop {
                self.space();
                let key = self.string()?;
                self.space();
                self.expect(b":")?;
                let mut value = String::new();
                self.value(depth + 1, &mut value)?;
                members.push((key, value));
                self.space();
                match self.next() {
                    Some(b',') => {}
                    Some(b'}') => break,
                    _ => return Err(Malformed),
                }
            }
        }
        // By the bytes of the key in UTF-8, which is also code point order.
        members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if members.windows(2).any(|pair| match pair {
            [a, b] => a.0 == b.0,
            _ => false,
        }) {
            return Err(Malformed);
        }
        out.push('{');
        for (index, (key, value)) in members.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            write_string(key, out);
            out.push(':');
            out.push_str(value);
        }
        out.push('}');
        Ok(())
    }
    fn array(&mut self, depth: usize, out: &mut String) -> Result<(), Malformed> {
        self.at += 1;
        out.push('[');
        self.space();
        if self.peek() == Some(b']') {
            self.at += 1;
        } else {
            loop {
                self.value(depth + 1, out)?;
                self.space();
                match self.next() {
                    Some(b',') => out.push(','),
                    Some(b']') => break,
                    _ => return Err(Malformed),
                }
            }
        }
        out.push(']');
        Ok(())
    }
    fn hex4(&mut self) -> Result<u32, Malformed> {
        let mut unit = 0u32;
        for _ in 0..4 {
            let digit = (self.next().ok_or(Malformed)? as char)
                .to_digit(16)
                .ok_or(Malformed)?;
            unit = unit * 16 + digit;
        }
        Ok(unit)
    }
    /// The characters of a string, with its escapes resolved.
    fn string(&mut self) -> Result<String, Malformed> {
        if self.next() != Some(b'"') {
            return Err(Malformed);
        }
        let mut raw: Vec<u8> = Vec::new();
        loop {
            match self.next().ok_or(Malformed)? {
                b'"' => break,
                b'\\' => {
                    let character = match self.next().ok_or(Malformed)? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let unit = self.hex4()?;
                            let point = if (0xD800..0xDC00).contains(&unit) {
                                self.expect(b"\\u")?;
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return Err(Malformed);
                                }
                                0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                            } else {
                                unit
                            };
                            char::from_u32(point).ok_or(Malformed)?
                        }
                        _ => return Err(Malformed),
                    };
                    let mut buffer = [0u8; 4];
                    raw.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                }
                byte if byte < 0x20 => return Err(Malformed),
                byte => raw.push(byte),
            }
        }
        String::from_utf8(raw).map_err(|_| Malformed)
    }
    fn digits(&mut self) -> &[u8] {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.bytes.get(start..self.at).unwrap_or_default()
    }
    /// A number as a plain decimal: no exponent, no zero that carries no
    /// value, no sign on zero. `1.50`, `15e-1` and `1.5` are one number.
    fn number(&mut self, out: &mut String) -> Result<(), Malformed> {
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        let whole = self.digits().to_vec();
        if whole.is_empty() || (whole.len() > 1 && whole.first() == Some(&b'0')) {
            return Err(Malformed);
        }
        let mut fraction = Vec::new();
        if self.peek() == Some(b'.') {
            self.at += 1;
            fraction = self.digits().to_vec();
            if fraction.is_empty() {
                return Err(Malformed);
            }
        }
        let mut exponent: i64 = 0;
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            let minus = match self.peek() {
                Some(b'-') => {
                    self.at += 1;
                    true
                }
                Some(b'+') => {
                    self.at += 1;
                    false
                }
                _ => false,
            };
            let digits = self.digits();
            // PostgreSQL never prints an exponent for `jsonb`; a number that
            // would need thousands of zeros is refused, not expanded.
            if digits.is_empty() || digits.len() > 4 {
                return Err(Malformed);
            }
            for digit in digits {
                exponent = exponent * 10 + i64::from(digit - b'0');
            }
            if minus {
                exponent = -exponent;
            }
        }
        // The digits of the number, and how many of them are before the point.
        let mut point = whole.len() as i64 + exponent;
        let mut all = whole;
        all.extend_from_slice(&fraction);
        let leading = all.iter().take_while(|digit| **digit == b'0').count();
        let significant: Vec<u8> = all.iter().skip(leading).copied().collect();
        point -= leading as i64;
        let kept = significant
            .iter()
            .rposition(|digit| *digit != b'0')
            .map_or(0, |last| last + 1);
        let significant: String = significant
            .iter()
            .take(kept)
            .map(|digit| *digit as char)
            .collect();
        if significant.is_empty() {
            out.push('0');
            return Ok(());
        }
        if negative {
            out.push('-');
        }
        let count = significant.len() as i64;
        if point <= 0 {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', point.unsigned_abs() as usize));
            out.push_str(&significant);
        } else if point >= count {
            out.push_str(&significant);
            out.extend(std::iter::repeat_n('0', (point - count) as usize));
        } else {
            let (before, after) = significant.split_at(point as usize);
            out.push_str(before);
            out.push('.');
            out.push_str(after);
        }
        Ok(())
    }
}
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}
/// JSON in one form, whatever the order of its keys and the spelling of its
/// numbers and escapes: no white space; the keys of an object sorted by
/// their UTF-8 bytes; a number as a plain decimal; a string in UTF-8 with
/// only `"`, `\` and the characters below U+0020 escaped, those as `\u00xx`.
/// Numbers are kept digit for digit, never read as floating point.
pub fn canonical_json(text: &str) -> Result<String, Malformed> {
    let mut parser = Json {
        bytes: text.as_bytes(),
        at: 0,
    };
    let mut out = String::with_capacity(text.len());
    parser.value(0, &mut out)?;
    parser.space();
    if parser.at == parser.bytes.len() {
        Ok(out)
    } else {
        Err(Malformed)
    }
}

fn field(out: &mut Vec<u8>, tag: u8, value: Option<&str>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(tag);
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
    }
}
/// The bytes of a row that a link's hash covers. Every field says how long
/// it is, so no value can pass for another or run into the next.
pub fn canonical_row(row: &Row) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + row.details.len());
    out.extend_from_slice(ROW_LABEL);
    let uuid = |id: Uuid| id.hyphenated().to_string();
    field(&mut out, 1, Some(&uuid(row.id)));
    field(&mut out, 1, row.actor_id.map(uuid).as_deref());
    field(&mut out, 1, Some(&row.action));
    field(&mut out, 1, row.target_type.as_deref());
    field(&mut out, 1, row.target_id.map(uuid).as_deref());
    field(&mut out, 1, row.ip.as_deref());
    match canonical_json(&row.details) {
        Ok(details) => field(&mut out, 1, Some(&details)),
        // Never seen from `jsonb`, except for nesting beyond `MAX_DEPTH`.
        // The stored text is still one fixed text for one stored value, and
        // the tag keeps it apart from a canonical form.
        Err(Malformed) => field(&mut out, 2, Some(&row.details)),
    }
    field(&mut out, 1, Some(&row.created_at));
    field(&mut out, 1, Some(&row.seq.to_string()));
    field(&mut out, 1, Some(&row.txid));
    out
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    // Upper-case hex is another spelling of the same bytes; a stored hash
    // is always lower-case.
    (hex(&out) == text).then_some(out)
}
/// The hash of the link at `position` over `row`, in the run of links of
/// its key that began at `segment_start`, after a link whose hash is `prev`;
/// lower-case hex. `None` when `prev` is not a hash.
pub fn link_hash(
    crypto: &Crypto,
    position: i64,
    segment_start: i64,
    prev: &str,
    row: &[u8],
) -> Option<String> {
    let prev = unhex(prev)?;
    let mut input = Vec::with_capacity(LINK_LABEL.len() + 48 + row.len());
    input.extend_from_slice(LINK_LABEL);
    input.extend_from_slice(&(position as u64).to_be_bytes());
    input.extend_from_slice(&(segment_start as u64).to_be_bytes());
    input.extend_from_slice(&prev);
    input.extend_from_slice(row);
    Some(hex(&crypto.chain_mac(&input)))
}

/// Where the run of links of `key_id` begins for a link at `position` that
/// follows `head` (its key and the start of its run): the run goes on from
/// the head, or begins with this link when the head is another key's or
/// there is none.
fn segment_start_after(head: Option<(&str, i64)>, key_id: &str, position: i64) -> i64 {
    match head {
        Some((head_key, start)) if head_key == key_id => start,
        _ => position,
    }
}

/// The last link of the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct Head {
    pub position: i64,
    pub hash: String,
    pub key_id: String,
    /// Where the run of links of that key began.
    #[serde(skip)]
    pub segment_start: i64,
    #[serde(skip)]
    pub txid: String,
    #[serde(skip)]
    pub seq: i64,
    /// As JSON prints a time; text, because a changed row can hold a time
    /// that no date type can.
    pub sealed_at: String,
}
const HEAD_COLUMNS: &str =
    "position,hash,key_id,segment_start,txid::text AS txid,seq,to_json(sealed_at)#>>'{}' AS sealed_at";
/// The last link, or `None` when nothing is sealed yet.
pub async fn head(connection: &mut PgConnection) -> Result<Option<Head>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {HEAD_COLUMNS} FROM audit_chain ORDER BY position DESC LIMIT 1"
    ))
    .fetch_optional(connection)
    .await
}

/// What one run of the sealer did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Links appended.
    pub rows: usize,
    /// The last link after the run.
    pub head: Option<Head>,
    /// The key of the link before, when this run began with another key.
    pub previous_key: Option<String>,
}
/// Append up to `limit` links for the audit rows that are safe to seal, in
/// chain order, in one transaction. `None` when another session is sealing.
///
/// The transaction holds an advisory lock, so two sealers never read the
/// same head; and should they, the primary key on `position` lets only one
/// of two appends to the same head commit.
pub async fn seal(db: &PgPool, crypto: &Crypto, limit: i64) -> Result<Option<Sealed>, sqlx::Error> {
    let mut tx = db.begin().await?;
    if !try_lock(&mut tx, SEAL_LOCK).await? {
        return Ok(None);
    }
    let before = head(&mut tx).await?;
    // One statement, so the rows and the limit below which they are final
    // come from one snapshot.
    let rows: Vec<Row> = match &before {
        Some(head) => {
            sqlx::query_as(&format!(
                "SELECT {ROW_COLUMNS} FROM audit_log a
                 WHERE a.txid<pg_snapshot_xmin(pg_current_snapshot())
                   AND (a.txid,a.seq)>($2::text::xid8,$3)
                 ORDER BY a.txid,a.seq LIMIT $1"
            ))
            .bind(limit)
            .bind(&head.txid)
            .bind(head.seq)
            .fetch_all(&mut *tx)
            .await?
        }
        None => {
            sqlx::query_as(&format!(
                "SELECT {ROW_COLUMNS} FROM audit_log a
                 WHERE a.txid<pg_snapshot_xmin(pg_current_snapshot())
                 ORDER BY a.txid,a.seq LIMIT $1"
            ))
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?
        }
    };
    if rows.is_empty() {
        return Ok(Some(Sealed {
            rows: 0,
            head: before,
            previous_key: None,
        }));
    }
    let key_id = crypto.chain_key_id();
    let mut position = before.as_ref().map_or(0, |head| head.position);
    let segment_start = segment_start_after(
        before
            .as_ref()
            .map(|head| (head.key_id.as_str(), head.segment_start)),
        &key_id,
        position + 1,
    );
    let mut prev = before
        .as_ref()
        .map_or_else(|| GENESIS.to_owned(), |head| head.hash.clone());
    let (mut positions, mut ids, mut txids, mut seqs, mut prevs, mut hashes) = (
        Vec::with_capacity(rows.len()),
        Vec::with_capacity(rows.len()),
        Vec::with_capacity(rows.len()),
        Vec::with_capacity(rows.len()),
        Vec::with_capacity(rows.len()),
        Vec::with_capacity(rows.len()),
    );
    for row in &rows {
        position += 1;
        // A head whose hash is not a hash was written by someone else. The
        // chain is already broken there; do not build on it.
        let hash = link_hash(crypto, position, segment_start, &prev, &canonical_row(row))
            .ok_or_else(|| {
                sqlx::Error::Protocol("the head of the audit chain is damaged".into())
            })?;
        positions.push(position);
        ids.push(row.id);
        txids.push(row.txid.clone());
        seqs.push(row.seq);
        prevs.push(std::mem::replace(&mut prev, hash.clone()));
        hashes.push(hash);
    }
    sqlx::query(
        "INSERT INTO audit_chain(position,audit_id,txid,seq,key_id,segment_start,prev_hash,hash)
         SELECT u.position,u.audit_id,u.txid::xid8,u.seq,$5,$8,u.prev_hash,u.hash
         FROM UNNEST($1::bigint[],$2::uuid[],$3::text[],$4::bigint[],$6::text[],$7::text[])
           AS u(position,audit_id,txid,seq,prev_hash,hash)",
    )
    .bind(&positions)
    .bind(&ids)
    .bind(&txids)
    .bind(&seqs)
    .bind(&key_id)
    .bind(&prevs)
    .bind(&hashes)
    .bind(segment_start)
    .execute(&mut *tx)
    .await?;
    let after = head(&mut tx).await?;
    tx.commit().await?;
    Ok(Some(Sealed {
        rows: rows.len(),
        head: after,
        previous_key: before
            .filter(|head| head.key_id != key_id)
            .map(|head| head.key_id),
    }))
}

/// What is wrong with the chain, at the first place where something is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A sealed audit row no longer has the content its link was made for:
    /// the row, or the link, was changed.
    RowChanged,
    /// A link's audit row is gone: the row was deleted.
    RowMissing,
    /// An audit row sorts among the sealed rows and has no link: it was put
    /// in after the rows around it were sealed.
    RowInserted,
    /// A link does not follow the link before it: a link was deleted,
    /// moved, or put in.
    ChainBroken,
    /// The chain ends before a checkpoint that was saved outside: its end
    /// was cut off.
    ChainTruncated,
    /// The link at a saved checkpoint has another hash: the chain was
    /// rebuilt.
    CheckpointMismatch,
}
/// The first problem of a check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Problem {
    pub kind: Kind,
    /// The link where the chain stops verifying. For an inserted row, the
    /// first link after the place where the row sorts.
    pub position: i64,
    /// The audit row concerned, when there is one.
    pub audit_id: Option<Uuid>,
    pub seq: Option<i64>,
    pub message: String,
}
/// Links in a row that were sealed with a key that is not the current one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Segment {
    pub key_id: String,
    pub first_position: i64,
    pub last_position: i64,
}
/// The result of checking a range of links and their rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Outcome {
    /// `intact`: every link in the range verified with the current key.
    /// `partial`: nothing is wrong, but some links were sealed with another
    /// key and only their structure could be checked. `broken`: see `problem`.
    pub status: Status,
    /// The key the check was made with.
    pub key_id: String,
    pub from_position: i64,
    /// The last link checked; `from_position - 1` when the range is empty.
    pub to_position: i64,
    /// Links checked, and how many of them with the current key.
    pub links: i64,
    pub verified: i64,
    pub unverifiable: Vec<Segment>,
    pub problem: Option<Problem>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Intact,
    Partial,
    Broken,
}
impl Outcome {
    fn new(key_id: String, from: i64) -> Self {
        Self {
            status: Status::Intact,
            key_id,
            from_position: from,
            to_position: from - 1,
            links: 0,
            verified: 0,
            unverifiable: Vec::new(),
            problem: None,
        }
    }
    fn count(&mut self, position: i64, foreign_key: Option<&str>) {
        self.links += 1;
        self.to_position = position;
        let Some(key_id) = foreign_key else {
            self.verified += 1;
            return;
        };
        match self.unverifiable.last_mut() {
            Some(last) if last.key_id == key_id && last.last_position + 1 == position => {
                last.last_position = position;
            }
            _ => self.unverifiable.push(Segment {
                key_id: key_id.to_owned(),
                first_position: position,
                last_position: position,
            }),
        }
    }
    fn settle(mut self) -> Self {
        self.status = match (self.problem.is_some(), self.unverifiable.is_empty()) {
            (true, _) => Status::Broken,
            (false, true) => Status::Intact,
            (false, false) => Status::Partial,
        };
        self
    }
    /// Join the result of the next range onto this one.
    pub fn extend(&mut self, next: Outcome) {
        self.to_position = next.to_position.max(self.to_position);
        self.links += next.links;
        self.verified += next.verified;
        for segment in next.unverifiable {
            match self.unverifiable.last_mut() {
                Some(last)
                    if last.key_id == segment.key_id
                        && last.last_position + 1 == segment.first_position =>
                {
                    last.last_position = segment.last_position;
                }
                _ => self.unverifiable.push(segment),
            }
        }
        self.problem = self.problem.take().or(next.problem);
        *self = std::mem::replace(self, Outcome::new(String::new(), 1)).settle();
    }
}

#[derive(Debug, sqlx::FromRow)]
struct Link {
    position: i64,
    audit_id: Uuid,
    link_txid: String,
    link_seq: i64,
    key_id: String,
    segment_start: i64,
    prev_hash: String,
    hash: String,
    present: bool,
    #[sqlx(flatten)]
    row: MaybeRow,
}
/// [`Row`] from a left join: every column may be missing.
#[derive(Debug, sqlx::FromRow)]
struct MaybeRow {
    id: Option<Uuid>,
    actor_id: Option<Uuid>,
    action: Option<String>,
    target_type: Option<String>,
    target_id: Option<Uuid>,
    ip: Option<String>,
    details: Option<String>,
    created_at: Option<String>,
    seq: Option<i64>,
    txid: Option<String>,
}
impl MaybeRow {
    fn row(self) -> Option<Row> {
        Some(Row {
            id: self.id?,
            actor_id: self.actor_id,
            action: self.action?,
            target_type: self.target_type,
            target_id: self.target_id,
            ip: self.ip,
            details: self.details?,
            created_at: self.created_at?,
            seq: self.seq?,
            txid: self.txid?,
        })
    }
}
/// A place in the chain order. Transaction IDs are compared as numbers.
type Key = (u64, i64);
fn key(txid: &str, seq: i64) -> Option<Key> {
    Some((txid.parse().ok()?, seq))
}
fn problem(kind: Kind, position: i64, row: Option<(Uuid, i64)>, message: &str) -> Problem {
    Problem {
        kind,
        position,
        audit_id: row.map(|(id, _)| id),
        seq: row.map(|(_, seq)| seq),
        message: message.to_owned(),
    }
}
/// What the check of a link needs from the link before it.
#[derive(Debug, Clone)]
struct Prev {
    hash: String,
    /// Its place in the order; `None` before the first link.
    place: Option<Key>,
    /// Its key and where the run of that key began; `None` before the
    /// first link.
    run: Option<(String, i64)>,
}
/// The link before `from`, as the database has it. A check that begins in
/// the middle of the chain takes that link on trust, as it takes its hash.
async fn before(connection: &mut PgConnection, from: i64) -> Result<Option<Prev>, sqlx::Error> {
    if from <= 1 {
        return Ok(Some(Prev {
            hash: GENESIS.to_owned(),
            place: None,
            run: None,
        }));
    }
    let link: Option<(String, String, i64, String, i64)> = sqlx::query_as(
        "SELECT hash,txid::text,seq,key_id,segment_start FROM audit_chain WHERE position=$1",
    )
    .bind(from - 1)
    .fetch_optional(connection)
    .await?;
    Ok(link.map(|(hash, txid, seq, key_id, segment_start)| Prev {
        hash,
        place: key(&txid, seq),
        run: Some((key_id, segment_start)),
    }))
}
/// Whether a link's `segment_start` fits the link before it: the same start
/// when that link has the same key, the link's own position when it has
/// another key or there is none.
fn continues_run(position: i64, key_id: &str, segment_start: i64, prev: &Prev) -> bool {
    match &prev.run {
        Some((prev_key, prev_start)) if prev_key == key_id => segment_start == *prev_start,
        _ => segment_start == position,
    }
}
/// The first audit row that sorts in `(after, upto]` and has no link.
async fn inserted(
    connection: &mut PgConnection,
    after: Option<Key>,
    upto: Key,
    links: i64,
) -> Result<Option<(Uuid, i64, Key)>, sqlx::Error> {
    // Every link in the range has its row at the link's own place, so the
    // rows in the range are exactly the links' rows when there are as many.
    // Counting reads the index only; the search below runs after a mismatch.
    // Without a lower end the condition is left out, not made true by a
    // parameter, so that the index on (txid, seq) is read between the two
    // ends and no further whatever plan is cached.
    let lower = if after.is_some() {
        "AND (a.txid,a.seq)>($3::text::xid8,$4)"
    } else {
        ""
    };
    let count = format!(
        "SELECT count(*) FROM audit_log a WHERE (a.txid,a.seq)<=($1::text::xid8,$2) {lower}"
    );
    let mut query = sqlx::query_scalar(&count)
        .bind(upto.0.to_string())
        .bind(upto.1);
    if let Some((txid, seq)) = after {
        query = query.bind(txid.to_string()).bind(seq);
    }
    let count: i64 = query.fetch_one(&mut *connection).await?;
    if count == links {
        return Ok(None);
    }
    let search = format!(
        "SELECT a.id,a.seq,a.txid::text FROM audit_log a
         WHERE (a.txid,a.seq)<=($1::text::xid8,$2) {lower}
           AND NOT EXISTS (SELECT 1 FROM audit_chain c WHERE c.audit_id=a.id)
         ORDER BY a.txid,a.seq LIMIT 1"
    );
    let mut query = sqlx::query_as(&search)
        .bind(upto.0.to_string())
        .bind(upto.1);
    if let Some((txid, seq)) = after {
        query = query.bind(txid.to_string()).bind(seq);
    }
    let extra: Option<(Uuid, i64, String)> = query.fetch_optional(connection).await?;
    Ok(extra.and_then(|(id, seq, txid)| Some((id, seq, key(&txid, seq)?))))
}
/// Check the links from `from` to `to` and the audit rows they seal, and
/// report the first problem. Reads only.
///
/// For every link, in order: it has the next position; it names the hash of
/// the link before it; it sorts after the link before it; its audit row is
/// there, at the place the link names; its hash is the hash of that row; and
/// it continues the run of links of its key, or begins one after a link of
/// another key. The hash can be made again only for links sealed with
/// `crypto`'s key, so only for those is the run proved; for the others it
/// is compared as stored. Then: no audit row without a link sorts among the
/// rows of the range.
pub async fn verify(
    connection: &mut PgConnection,
    crypto: &Crypto,
    from: i64,
    to: i64,
) -> Result<Outcome, sqlx::Error> {
    let from = from.max(1);
    let key_id = crypto.chain_key_id();
    let mut outcome = Outcome::new(key_id.clone(), from);
    if to < from {
        return Ok(outcome);
    }
    let Some(mut prev) = before(&mut *connection, from).await? else {
        outcome.problem = Some(problem(
            Kind::ChainBroken,
            from - 1,
            None,
            "A link is missing from the chain",
        ));
        return Ok(outcome.settle());
    };
    let mut next = from;
    while next <= to && outcome.problem.is_none() {
        let last = (next + PAGE - 1).min(to);
        let links: Vec<Link> = sqlx::query_as(&format!(
            "SELECT c.position,c.audit_id,c.txid::text AS link_txid,c.seq AS link_seq,c.key_id,
                    c.segment_start,c.prev_hash,c.hash,a.id IS NOT NULL AS present,{ROW_COLUMNS}
             FROM audit_chain c LEFT JOIN audit_log a ON a.id=c.audit_id
             WHERE c.position BETWEEN $1 AND $2 ORDER BY c.position"
        ))
        .bind(next)
        .bind(last)
        .fetch_all(&mut *connection)
        .await?;
        // Where the rows of this page begin in the order, and the links
        // that were good before the first problem: place, position, and
        // the key when it is not the current one.
        let page_after = prev.place;
        let mut places: Vec<(Key, i64, Option<String>)> = Vec::with_capacity(links.len());
        for link in links {
            let position = next + places.len() as i64;
            match check(crypto, &key_id, position, &prev, link) {
                Ok((good, place, foreign)) => {
                    prev = good;
                    places.push((place, position, foreign));
                }
                Err(found) => {
                    outcome.problem = Some(found);
                    break;
                }
            }
        }
        let good = places.len() as i64;
        // A row without a link, among the rows that were good, comes
        // first: the chain is good only up to where that row sorts.
        let mut upto = next + good;
        if let Some((last_place, _, _)) = places.last() {
            if let Some((id, seq, place)) =
                inserted(&mut *connection, page_after, *last_place, good).await?
            {
                upto = places
                    .iter()
                    .find(|(link, _, _)| *link > place)
                    .map_or(upto, |(_, position, _)| *position);
                outcome.problem = Some(Problem {
                    kind: Kind::RowInserted,
                    position: upto,
                    audit_id: Some(id),
                    seq: Some(seq),
                    message: "An audit row was added among rows that were already sealed"
                        .to_owned(),
                });
            }
        }
        for (_, position, foreign) in places.iter().filter(|(_, position, _)| *position < upto) {
            outcome.count(*position, foreign.as_deref());
        }
        if outcome.problem.is_none() && next + good <= last {
            // The page ended early: a position is not there.
            outcome.problem = Some(problem(
                Kind::ChainBroken,
                next + good,
                None,
                "A link is missing from the chain",
            ));
        }
        next = last + 1;
    }
    Ok(outcome.settle())
}
/// Check one link against the link before it and its row. Returns what the
/// next link needs of it, its place in the order, and its key when that is
/// not the current one.
fn check(
    crypto: &Crypto,
    key_id: &str,
    position: i64,
    prev: &Prev,
    link: Link,
) -> Result<(Prev, Key, Option<String>), Problem> {
    if link.position != position {
        return Err(problem(
            Kind::ChainBroken,
            position,
            None,
            "A link is missing from the chain",
        ));
    }
    let named = Some((link.audit_id, link.link_seq));
    if link.prev_hash != prev.hash {
        return Err(problem(
            Kind::ChainBroken,
            position,
            named,
            "A link does not follow the link before it: a link was removed, moved or put in",
        ));
    }
    let place = key(&link.link_txid, link.link_seq);
    let Some(place) = place.filter(|place| prev.place.is_none_or(|before| *place > before)) else {
        return Err(problem(
            Kind::ChainBroken,
            position,
            named,
            "A link is out of order: links were moved",
        ));
    };
    if !link.present {
        return Err(problem(
            Kind::RowMissing,
            position,
            named,
            "A sealed audit row was deleted",
        ));
    }
    let changed = || {
        problem(
            Kind::RowChanged,
            position,
            named,
            "A sealed audit row, or its link, was changed after it was sealed",
        )
    };
    let row = link.row.row().ok_or_else(changed)?;
    if row.seq != link.link_seq || row.txid != link.link_txid {
        return Err(changed());
    }
    let current = link.key_id == key_id;
    if current {
        let expected = link_hash(
            crypto,
            position,
            link.segment_start,
            &link.prev_hash,
            &canonical_row(&row),
        );
        // Not a comparison of secrets: both values are in the database.
        if expected.as_deref() != Some(link.hash.as_str()) {
            return Err(changed());
        }
    } else if unhex(&link.hash).is_none() {
        // Sealed with another key: the hash cannot be made again here, but
        // it must at least be a hash.
        return Err(changed());
    }
    // For a link of the current key the start of its run is now proved by
    // its hash. If it does not fit the link before, that link, or links
    // before that one, no longer name the key they were sealed with.
    if !continues_run(position, &link.key_id, link.segment_start, prev) {
        let message = if current {
            format!(
                "A link was relabelled: this link was sealed in a run of links of its key that \
                 began at position {}, and a link between there and here now names another key",
                link.segment_start
            )
        } else {
            "A link was relabelled: the start of its run of links does not fit the link before it"
                .to_owned()
        };
        return Err(problem(Kind::ChainBroken, position, named, &message));
    }
    let good = Prev {
        hash: link.hash,
        place: Some(place),
        run: Some((link.key_id.clone(), link.segment_start)),
    };
    Ok((good, place, (!current).then_some(link.key_id)))
}

/// A head that was seen outside the database: in a log line, or by a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub position: i64,
    pub hash: String,
    /// The key that sealed that link, when it was noted with the head.
    pub key_id: Option<String>,
}
/// Whether the chain still holds the link of a checkpoint. A link, once
/// made, never changes, so a checkpoint that no longer matches means the
/// chain was cut, rebuilt or relabelled after the checkpoint was taken. The
/// name of the key is part of the comparison: it is not inside the link's
/// hash, and relabelling the links of the current key up to the head is
/// what no later link can show.
pub async fn check_checkpoint(
    connection: &mut PgConnection,
    checkpoint: &Checkpoint,
) -> Result<Option<Problem>, sqlx::Error> {
    let stored: Option<(String, String)> =
        sqlx::query_as("SELECT hash,key_id FROM audit_chain WHERE position=$1")
            .bind(checkpoint.position)
            .fetch_optional(&mut *connection)
            .await?;
    let found = match stored {
        Some((hash, _)) if hash != checkpoint.hash => Some(problem(
            Kind::CheckpointMismatch,
            checkpoint.position,
            None,
            "The link at the checkpoint has another hash: the chain was rebuilt",
        )),
        Some((_, key_id))
            if checkpoint
                .key_id
                .as_ref()
                .is_some_and(|expected| *expected != key_id) =>
        {
            Some(problem(
                Kind::CheckpointMismatch,
                checkpoint.position,
                None,
                "The link at the checkpoint names another key than it was sealed with: it was relabelled",
            ))
        }
        Some(_) => None,
        None => {
            let end = head(connection).await?.map_or(0, |head| head.position);
            Some(if end < checkpoint.position {
                problem(
                    Kind::ChainTruncated,
                    end + 1,
                    None,
                    "The chain ends before the checkpoint: its end was removed",
                )
            } else {
                problem(
                    Kind::ChainBroken,
                    checkpoint.position,
                    None,
                    "A link is missing from the chain",
                )
            })
        }
    };
    Ok(found)
}

/// How far sealing is behind.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Backlog {
    /// Audit rows after the last sealed one.
    pub unsealed: i64,
    /// When the oldest of them was written, as JSON prints a time.
    pub oldest_unsealed_at: Option<String>,
    /// How long ago that was.
    pub oldest_unsealed_seconds: Option<f64>,
}
/// Count the audit rows that are not sealed yet.
pub async fn backlog(
    connection: &mut PgConnection,
    head: Option<&Head>,
) -> Result<Backlog, sqlx::Error> {
    // Only finite times: a row with an infinite one must not make the
    // count fail, and has no age.
    const COLUMNS: &str = "count(*),
        to_json(min(a.created_at) FILTER (WHERE isfinite(a.created_at)))#>>'{}',
        extract(epoch FROM clock_timestamp()
            -min(a.created_at) FILTER (WHERE isfinite(a.created_at)))::float8";
    type Counts = (i64, Option<String>, Option<f64>);
    let (unsealed, oldest_unsealed_at, oldest_unsealed_seconds): Counts = match head {
        Some(head) => {
            sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM audit_log a WHERE (a.txid,a.seq)>($1::text::xid8,$2)"
            ))
            .bind(&head.txid)
            .bind(head.seq)
            .fetch_one(connection)
            .await?
        }
        None => {
            sqlx::query_as(&format!("SELECT {COLUMNS} FROM audit_log a"))
                .fetch_one(connection)
                .await?
        }
    };
    Ok(Backlog {
        unsealed,
        oldest_unsealed_at,
        // A clock that is behind the row's is no negative wait.
        oldest_unsealed_seconds: oldest_unsealed_seconds.map(|seconds| seconds.max(0.0)),
    })
}

/// What the background check has stored.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verification {
    /// The last pass that ended: at the head, or at a problem.
    pub result: Option<Outcome>,
    pub finished_at: Option<String>,
    /// How long ago that pass ended.
    pub finished_seconds: Option<f64>,
    /// The pass that is running, when one is: the last link it checked.
    pub position: i64,
    pub pass_started_at: Option<String>,
}
/// Read the state of the background check.
pub async fn verification(connection: &mut PgConnection) -> Result<Verification, sqlx::Error> {
    type Stored = (
        i64,
        Option<String>,
        Option<serde_json::Value>,
        Option<String>,
        Option<f64>,
    );
    let (position, pass_started_at, result, finished_at, finished_seconds): Stored =
        sqlx::query_as(
            "SELECT position,to_json(pass_started_at)#>>'{}',result,to_json(finished_at)#>>'{}',
                CASE WHEN isfinite(finished_at) THEN
                  GREATEST(extract(epoch FROM clock_timestamp()-finished_at),0)::float8 END
         FROM audit_verification",
        )
        .fetch_one(connection)
        .await?;
    Ok(Verification {
        // A result this version cannot read counts as no result.
        result: result.and_then(|value| serde_json::from_value(value).ok()),
        finished_at,
        finished_seconds,
        position,
        pass_started_at,
    })
}
/// What one step of the background check did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Another session is checking, or the next pass is not due.
    Idle,
    /// Checked links up to this position; the pass goes on.
    Checked { links: i64, position: i64 },
    /// The pass ended, at the head or at a problem.
    Finished { links: i64, outcome: Outcome },
}
/// Check the next `slice` links of the running pass, or begin a pass when
/// the last one began at least `every_seconds` ago. Progress and the result
/// are stored in `audit_verification`, so that any node can continue the
/// pass and report it. The audit log and the chain are only read.
pub async fn verify_step(
    db: &PgPool,
    crypto: &Crypto,
    slice: i64,
    every_seconds: f64,
) -> Result<Step, sqlx::Error> {
    let mut tx = db.begin().await?;
    if !try_lock(&mut tx, VERIFY_LOCK).await? {
        return Ok(Step::Idle);
    }
    let (position, progress, due): (i64, serde_json::Value, bool) = sqlx::query_as(
        "SELECT position,progress,
                pass_started_at IS NULL OR pass_started_at<=now()-make_interval(secs=>$1)
         FROM audit_verification",
    )
    .bind(every_seconds)
    .fetch_one(&mut *tx)
    .await?;
    let running: Option<Outcome> = serde_json::from_value(progress).ok();
    // A pass that another key began is begun again, not continued.
    let running = running.filter(|pass| position > 0 && pass.key_id == crypto.chain_key_id());
    if running.is_none() && !due {
        return Ok(Step::Idle);
    }
    let end = head(&mut tx).await?.map_or(0, |head| head.position);
    let from = running.as_ref().map_or(1, |pass| pass.to_position + 1);
    let to = (from + slice - 1).min(end);
    let step = verify(&mut tx, crypto, from, to).await?;
    let links = step.links;
    let began = running.is_none();
    let mut pass = running.unwrap_or_else(|| Outcome::new(crypto.chain_key_id(), 1));
    pass.extend(step);
    let finished = pass.problem.is_some() || to >= end;
    // The transaction takes an ID only here, at its end: while it reads, it
    // does not hold sealing back.
    if finished {
        sqlx::query(
            "UPDATE audit_verification SET position=0,progress='{}',result=$1,finished_at=clock_timestamp(),
             pass_started_at=CASE WHEN $2 THEN now() ELSE pass_started_at END",
        )
        .bind(serde_json::json!(pass))
        .bind(began)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query(
            "UPDATE audit_verification SET position=$1,progress=$2,
             pass_started_at=CASE WHEN $3 THEN now() ELSE pass_started_at END",
        )
        .bind(pass.to_position)
        .bind(serde_json::json!(pass))
        .bind(began)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(if finished {
        Step::Finished {
            links,
            outcome: pass,
        }
    } else {
        Step::Checked {
            links,
            position: pass.to_position,
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn first() -> Row {
        Row {
            id: "11111111-2222-4333-8444-555555555555".parse().unwrap(),
            actor_id: Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".parse().unwrap()),
            action: "query.execute".into(),
            target_type: Some("cluster".into()),
            target_id: Some("99999999-8888-4777-8666-555555555555".parse().unwrap()),
            ip: Some("10.1.2.3/32".into()),
            // As `jsonb` prints it: its own key order, a space after `:` and `,`.
            details: r#"{"status": "running", "query_id": "q", "agent_id": null}"#.into(),
            created_at: "1795255200123456".into(),
            seq: 7,
            txid: "4242".into(),
        }
    }
    fn second() -> Row {
        Row {
            id: "11111111-2222-4333-8444-555555555556".parse().unwrap(),
            actor_id: None,
            action: "approval.expire".into(),
            target_type: None,
            target_id: None,
            ip: None,
            details: "{}".into(),
            created_at: "1795255200123457".into(),
            seq: 8,
            txid: "4243".into(),
        }
    }

    #[test]
    fn json_has_one_form_whatever_its_key_order_spacing_escapes_and_number_spelling() {
        // The expected texts were made by an independent implementation
        // (Python: json.loads with Decimal numbers, keys sorted by UTF-8).
        assert_eq!(
            canonical_json(
                r#"{"b": 1.50, "a": 1000, "aa": "é\n\u0001", "c": [true, null, {"y": -0.0, "x": 1e3}], "é": "\ud83d\ude00/"}"#
            )
            .unwrap(),
            r#"{"a":1000,"aa":"é\u000a\u0001","b":1.5,"c":[true,null,{"x":1000,"y":0}],"é":"😀/"}"#
        );
        assert_eq!(
            canonical_json(
                "[1.0, 1, 1.00, 100, 0.001, 12345678901234567890123.4500, 1E-2, -15e-1]"
            )
            .unwrap(),
            "[1,1,1,100,0.001,12345678901234567890123.45,0.01,-1.5]"
        );
        // Key order and white space do not matter; `jsonb` chooses its own.
        let forms = [
            r#"{"a":{"x":1,"y":[2,3]},"b":"t"}"#,
            r#"{"b": "t", "a": {"y": [2, 3], "x": 1}}"#,
            " {\n\t\"b\" : \"\\u0074\" ,\r\"a\":{\"y\":[2.0,3e0],\"x\":10e-1}} ",
        ];
        for form in forms {
            assert_eq!(canonical_json(form).unwrap(), forms[0], "{form}");
        }
        // A number is kept digit for digit: two that differ far below the
        // precision of a float stay different.
        assert_ne!(
            canonical_json("12345678901234567890123").unwrap(),
            canonical_json("12345678901234567890124").unwrap()
        );
        assert_ne!(
            canonical_json("0.10000000000000000001").unwrap(),
            canonical_json("0.1").unwrap()
        );
        // What differs in value differs in form.
        for (a, b) in [
            (r#"{"a":1}"#, r#"{"a":"1"}"#),
            (r#"{"a":null}"#, "{}"),
            (r#"["a","b"]"#, r#"["b","a"]"#),
            (r#""a\"b""#, r#""a\\b""#),
            ("[[]]", "[]"),
            ("1", "-1"),
            ("10", "1"),
            (r#""é""#, r#""e""#),
        ] {
            assert_ne!(canonical_json(a).unwrap(), canonical_json(b).unwrap());
        }
        for (given, expected) in [
            ("0", "0"),
            ("-0", "0"),
            ("0.0", "0"),
            ("0e5", "0"),
            ("120", "120"),
            ("1.2e2", "120"),
            ("1.2e1", "12"),
            ("1.2e0", "1.2"),
            ("12e-1", "1.2"),
            ("12e-2", "0.12"),
            ("12e-3", "0.012"),
            ("-0.00120", "-0.0012"),
            ("1e+2", "100"),
            (
                r#""\u00e9\t\/\b\f\r""#,
                "\"é\\u0009/\\u0008\\u000c\\u000d\"",
            ),
            (r#""\u007f\u2028""#, "\"\u{7f}\u{2028}\""),
        ] {
            assert_eq!(canonical_json(given).unwrap(), expected, "{given}");
        }
    }

    #[test]
    fn text_that_is_not_json_is_refused_not_guessed() {
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        for refused in [
            "",
            "{",
            "{}x",
            r#"{"a":1,"a":2}"#,
            r#"{"a":1,}"#,
            "[1,]",
            "01",
            "1.",
            ".5",
            "1e",
            "1e99999",
            "+1",
            "nul",
            "\"a",
            "\"\u{1}\"",
            r#""\x""#,
            r#""\ud83d""#,
            r#""\ud83dA""#,
            r#""\ude00""#,
            r#"{a:1}"#,
            deep.as_str(),
        ] {
            assert_eq!(canonical_json(refused), Err(Malformed), "{refused:?}");
        }
        // The deepest nesting that is accepted.
        let most = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert_eq!(canonical_json(&most).unwrap(), most);
    }

    #[test]
    fn a_row_is_encoded_with_every_field_and_no_field_can_pass_for_another() {
        // Made by an independent implementation of the encoding in Python.
        assert_eq!(
            hex(&canonical_row(&first())),
            "7664612d61756469742d726f772d7631010000002431313131313131312d323232322d343333332d\
             383434342d353535353535353535353535010000002461616161616161612d626262622d34636363\
             2d386464642d656565656565656565656565010000000d71756572792e6578656375746501000000\
             07636c7573746572010000002439393939393939392d383838382d343737372d383636362d353535\
             353535353535353535010000000b31302e312e322e332f333201000000337b226167656e745f6964\
             223a6e756c6c2c2271756572795f6964223a2271222c22737461747573223a2272756e6e696e6722\
             7d010000001031373935323535323030313233343536010000000137010000000434323432"
        );
        assert_eq!(
            hex(&canonical_row(&second())),
            "7664612d61756469742d726f772d7631010000002431313131313131312d323232322d343333332d\
             383434342d35353535353535353535353600010000000f617070726f76616c2e6578706972650000\
             0001000000027b7d010000001031373935323535323030313233343537010000000138010000000434\
             323433"
        );
        // Every column changes the bytes.
        let base = canonical_row(&first());
        let other: Uuid = "11111111-2222-4333-8444-555555555557".parse().unwrap();
        type Change = fn(&mut Row, Uuid);
        let changes: [(&str, Change); 10] = [
            ("id", |row, other| row.id = other),
            ("actor_id", |row, other| row.actor_id = Some(other)),
            ("action", |row, _| row.action.push('x')),
            ("target_type", |row, _| {
                row.target_type = Some("agent".into())
            }),
            ("target_id", |row, other| row.target_id = Some(other)),
            ("ip", |row, _| row.ip = Some("10.1.2.3/24".into())),
            ("details", |row, _| {
                row.details = r#"{"status":"ok","query_id":"q","agent_id":null}"#.into()
            }),
            ("created_at", |row, _| {
                row.created_at = "1795255200123457".into()
            }),
            ("seq", |row, _| row.seq = 9),
            ("txid", |row, _| row.txid = "4243".into()),
        ];
        for (column, change) in changes {
            let mut row = first();
            change(&mut row, other);
            assert_ne!(canonical_row(&row), base, "{column}");
        }
        // NULL is not an empty value, and a value cannot slide into the
        // field next to it.
        let mut null = second();
        let mut blank = second();
        null.target_type = None;
        blank.target_type = Some(String::new());
        assert_ne!(canonical_row(&null), canonical_row(&blank));
        let (mut left, mut right) = (second(), second());
        left.action = "ab".into();
        left.target_type = Some("c".into());
        right.action = "a".into();
        right.target_type = Some("bc".into());
        assert_ne!(canonical_row(&left), canonical_row(&right));
        // A value that looks like the framing of two fields is one field.
        let mut forged = second();
        forged.action = "a\u{1}\u{0}\u{0}\u{0}\u{1}b".into();
        let mut split = second();
        split.action = "a".into();
        split.target_type = Some("b".into());
        assert_ne!(canonical_row(&forged), canonical_row(&split));
        // The order of the keys of `details` is not content.
        let mut reordered = first();
        reordered.details = r#"{"agent_id":null,"query_id":"q","status":"running"}"#.into();
        assert_eq!(canonical_row(&reordered), base);
        // Unicode is hashed as UTF-8, whatever escape spelled it.
        let (mut plain, mut escaped) = (second(), second());
        plain.details = r#"{"task":"café ☕ 😀"}"#.into();
        escaped.details = r#"{"task":"caf\u00e9 \u2615 \ud83d\ude00"}"#.into();
        assert_eq!(canonical_row(&plain), canonical_row(&escaped));
        // Text that cannot be put in canonical form is hashed as stored,
        // under another tag, so it never equals a canonical form.
        let mut odd = second();
        odd.details = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        let bytes = canonical_row(&odd);
        let mut expected = Vec::new();
        field(&mut expected, 2, Some(&odd.details));
        assert!(bytes
            .windows(expected.len())
            .any(|window| window == expected.as_slice()));
    }

    #[test]
    fn link_hashes_match_answers_computed_independently() {
        // HMAC-SHA256 with the key SHA-256("visp-db-access audit chain key
        // v1\0" || master key), computed with Python's hmac and, for the
        // first link, with `openssl dgst -sha256 -mac HMAC`.
        let crypto = Crypto::new(&[3; 32]);
        let one = link_hash(&crypto, 1, 1, GENESIS, &canonical_row(&first())).unwrap();
        assert_eq!(
            one,
            "a34e37a372f82349c4c347bb41689fe7c8374cfb725df9580d8a81f093a9ee04"
        );
        let two = link_hash(&crypto, 2, 1, &one, &canonical_row(&second())).unwrap();
        assert_eq!(
            two,
            "515142eb3ce0973af2bebc04a32af93b204887c84758f759ba12f5fc6758f3cf"
        );
        // The position, the start of the run, the link before and the key
        // are all in the hash.
        assert_ne!(
            link_hash(&crypto, 3, 1, &one, &canonical_row(&second())).unwrap(),
            two
        );
        assert_eq!(
            link_hash(&crypto, 2, 2, &one, &canonical_row(&second())).unwrap(),
            "37e44b0d90713d453ff82a3d0a1f6a89c64110b2b6ca7245a06e2e6be526684a"
        );
        assert_ne!(
            link_hash(&crypto, 2, 1, GENESIS, &canonical_row(&second())).unwrap(),
            two
        );
        // A previous hash that is not 32 bytes of lower-case hex is refused.
        for bad in [
            "",
            "00",
            &one.to_uppercase(),
            &format!("{one}00"),
            &"zz".repeat(32),
        ] {
            assert_eq!(link_hash(&crypto, 2, 1, bad, b""), None, "{bad}");
        }
    }

    #[test]
    fn another_master_key_starts_a_segment_that_binds_the_one_before() {
        let old = Crypto::new(&[3; 32]);
        let new = Crypto::new(&[4; 32]);
        assert_ne!(old.chain_key_id(), new.chain_key_id());
        let one = link_hash(&old, 1, 1, GENESIS, &canonical_row(&first())).unwrap();
        let two = link_hash(&old, 2, 1, &one, &canonical_row(&second())).unwrap();
        // The first link of the new segment is made over the last hash of
        // the old one and names itself as the start of its run; computed
        // independently with the new key.
        let three = link_hash(&new, 3, 3, &two, &canonical_row(&second())).unwrap();
        assert_eq!(
            three,
            "b218e77fb42f384d8e19d8e16d39967ae663033822dd0120712026a0a3e4722d"
        );
        // Another end of the old segment gives another first link.
        assert_ne!(
            link_hash(&new, 3, 3, &one, &canonical_row(&second())).unwrap(),
            three
        );
        // The old key does not make the new segment's links.
        assert_ne!(
            link_hash(&old, 3, 3, &two, &canonical_row(&second())).unwrap(),
            three
        );
        // Segments are counted by key, in a row.
        let mut outcome = Outcome::new(new.chain_key_id(), 1);
        outcome.count(1, Some("old"));
        outcome.count(2, Some("old"));
        outcome.count(3, None);
        outcome.count(4, Some("old"));
        let outcome = outcome.settle();
        assert_eq!(outcome.status, Status::Partial);
        assert_eq!((outcome.links, outcome.verified), (4, 1));
        assert_eq!(
            outcome.unverifiable,
            [
                Segment {
                    key_id: "old".into(),
                    first_position: 1,
                    last_position: 2
                },
                Segment {
                    key_id: "old".into(),
                    first_position: 4,
                    last_position: 4
                },
            ]
        );
    }

    /// A chain in memory, sealed as the sealer seals: one link per key in
    /// `keys`, in order.
    fn sealed(keys: &[&Crypto]) -> Vec<Link> {
        let mut links: Vec<Link> = Vec::new();
        for (index, crypto) in keys.iter().enumerate() {
            let position = index as i64 + 1;
            let mut row = second();
            row.id = Uuid::from_u128(position as u128);
            row.seq = position;
            row.txid = (100 + position).to_string();
            let key_id = crypto.chain_key_id();
            let head = links.last();
            let segment_start = segment_start_after(
                head.map(|head| (head.key_id.as_str(), head.segment_start)),
                &key_id,
                position,
            );
            let prev_hash = head.map_or_else(|| GENESIS.to_owned(), |head| head.hash.clone());
            let hash = link_hash(
                crypto,
                position,
                segment_start,
                &prev_hash,
                &canonical_row(&row),
            )
            .unwrap();
            links.push(Link {
                position,
                audit_id: row.id,
                link_txid: row.txid.clone(),
                link_seq: row.seq,
                key_id,
                segment_start,
                prev_hash,
                hash,
                present: true,
                row: MaybeRow {
                    id: Some(row.id),
                    actor_id: row.actor_id,
                    action: Some(row.action),
                    target_type: row.target_type,
                    target_id: row.target_id,
                    ip: row.ip,
                    details: Some(row.details),
                    created_at: Some(row.created_at),
                    seq: Some(row.seq),
                    txid: Some(row.txid),
                },
            });
        }
        links
    }
    fn copy(link: &Link) -> Link {
        Link {
            position: link.position,
            audit_id: link.audit_id,
            link_txid: link.link_txid.clone(),
            link_seq: link.link_seq,
            key_id: link.key_id.clone(),
            segment_start: link.segment_start,
            prev_hash: link.prev_hash.clone(),
            hash: link.hash.clone(),
            present: link.present,
            row: MaybeRow {
                id: link.row.id,
                actor_id: link.row.actor_id,
                action: link.row.action.clone(),
                target_type: link.row.target_type.clone(),
                target_id: link.row.target_id,
                ip: link.row.ip.clone(),
                details: link.row.details.clone(),
                created_at: link.row.created_at.clone(),
                seq: link.row.seq,
                txid: link.row.txid.clone(),
            },
        }
    }
    /// Walk `links` from position `from` with `crypto`, as `verify` does:
    /// how many links were verified, how many were another key's, and the
    /// first problem.
    fn walk(crypto: &Crypto, links: &[Link], from: i64) -> (i64, i64, Option<Problem>) {
        let before = (from > 1).then(|| &links[from as usize - 2]);
        let mut prev = Prev {
            hash: before.map_or_else(|| GENESIS.to_owned(), |link| link.hash.clone()),
            place: before.and_then(|link| key(&link.link_txid, link.link_seq)),
            run: before.map(|link| (link.key_id.clone(), link.segment_start)),
        };
        let (mut verified, mut foreign) = (0, 0);
        for link in &links[from as usize - 1..] {
            match check(
                crypto,
                &crypto.chain_key_id(),
                link.position,
                &prev,
                copy(link),
            ) {
                Ok((good, _, None)) => {
                    prev = good;
                    verified += 1;
                }
                Ok((good, _, Some(_))) => {
                    prev = good;
                    foreign += 1;
                }
                Err(found) => return (verified, foreign, Some(found)),
            }
        }
        (verified, foreign, None)
    }

    #[test]
    fn the_start_of_a_run_is_set_by_the_sealer_and_proved_by_the_hash() {
        let (a, b) = (Crypto::new(&[3; 32]), Crypto::new(&[4; 32]));
        // An honest history: key A, then B, then A again.
        let chain = sealed(&[&a, &a, &a, &b, &b, &a, &a, &a]);
        let starts: Vec<i64> = chain.iter().map(|link| link.segment_start).collect();
        assert_eq!(starts, [1, 1, 1, 4, 4, 6, 6, 6]);
        // Each key verifies its own runs and finds nothing wrong in the
        // other's: no false break.
        assert_eq!(walk(&a, &chain, 1), (6, 2, None));
        assert_eq!(walk(&b, &chain, 1), (2, 6, None));
        // A check that begins inside a run, at its first link, and at the
        // first link after another key's run.
        for from in 1..=8 {
            let (verified, foreign, found) = walk(&a, &chain, from);
            assert_eq!(found, None, "from {from}");
            assert_eq!(verified + foreign, 9 - from, "from {from}");
        }
        // A link that names its key says nothing by that: the name is not
        // in the hash, and this is what the attacks below use.
        let mut relabelled = copy(&chain[1]);
        relabelled.key_id = b.chain_key_id();
        assert_eq!(relabelled.hash, chain[1].hash);
    }

    #[test]
    fn a_relabelled_link_inside_or_at_the_start_of_a_run_breaks_the_chain() {
        let (a, other) = (Crypto::new(&[3; 32]), "0123456789abcdef");
        let honest = || sealed(&[&a; 8]);
        let changed = |link: &mut Link| {
            link.row.action = Some("changed".into());
            link.key_id = other.into();
        };
        // The row at 4 is changed and its link alone is relabelled. Left as
        // it is, the link itself does not fit: it claims a run that began
        // at 1 after a link of another key.
        let mut chain = honest();
        changed(&mut chain[3]);
        let (verified, foreign, found) = walk(&a, &chain, 1);
        let found = found.unwrap();
        assert_eq!((verified, foreign), (3, 0));
        assert_eq!((found.kind, found.position), (Kind::ChainBroken, 4));
        assert!(found.message.contains("relabelled"), "{}", found.message);
        // With the stored start set to fit (it is not proved for a link of
        // another key), the next link gives it away: its hash says its run
        // began at 1, and the link before it is not of its key.
        chain[3].segment_start = 4;
        let (verified, foreign, found) = walk(&a, &chain, 1);
        let found = found.unwrap();
        assert_eq!((verified, foreign), (3, 1));
        assert_eq!((found.kind, found.position), (Kind::ChainBroken, 5));
        assert!(
            found.message.contains("relabelled") && found.message.contains("position 1"),
            "{}",
            found.message
        );
        // The start of the next link cannot be set to fit: it is in the hash.
        chain[4].segment_start = 5;
        let found = walk(&a, &chain, 1).2.unwrap();
        assert_eq!((found.kind, found.position), (Kind::RowChanged, 5));
        // The whole start of the run relabelled, up to and with the changed
        // row, as if another key had sealed it and this key began at 5.
        let mut chain = honest();
        for link in &mut chain[..4] {
            link.key_id = other.into();
        }
        chain[3].row.action = Some("changed".into());
        let (verified, foreign, found) = walk(&a, &chain, 1);
        let found = found.unwrap();
        assert_eq!((verified, foreign), (0, 4));
        assert_eq!((found.kind, found.position), (Kind::ChainBroken, 5));
        // A bounded check that begins after the relabelled links, inside
        // what is left of the run, sees links that follow each other.
        assert_eq!(walk(&a, &chain, 6), (3, 0, None));
        // ... and one that begins right behind them does not pass.
        assert_eq!(walk(&a, &chain, 5).2.unwrap().kind, Kind::ChainBroken);
        // Relabelled up to the head: no link of the key is left to object.
        // This is what only a checkpoint from outside shows.
        let mut chain = honest();
        for link in &mut chain[3..] {
            link.key_id = other.into();
            link.segment_start = 4;
        }
        chain[3].row.action = Some("changed".into());
        assert_eq!(walk(&a, &chain, 1), (3, 5, None));
    }
}
