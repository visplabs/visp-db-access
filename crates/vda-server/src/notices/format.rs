//! The two shapes a notice is sent in, and the signature of the first.
use super::Format;
use serde_json::{json, Value};
use uuid::Uuid;

/// The event name of the notice that "Send test" sends.
pub const TEST_EVENT: &str = "notice.test";
/// How long a name (cluster, environment, requester, agent) may be in a
/// notice, in characters.
pub const NAME_LIMIT: usize = 200;
/// Slack refuses a section text of more than 3000 characters.
const SLACK_TEXT_LIMIT: usize = 2900;

/// A request body and the headers that go with it.
#[derive(Debug, Clone)]
pub struct Rendered {
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
}

/// The signature of a notice, scheme `v1`: `v1=` and the HMAC-SHA256, in
/// lower-case hex, of `<timestamp>.<delivery id>.<body>` under `secret`.
///
/// The timestamp is signed, so a receiver that checks its age cannot be sent
/// an old notice again. The delivery id is signed, so a notice cannot be
/// passed off as another delivery to get past a receiver that drops repeats.
/// Neither can hold a dot, so the three parts cannot be split another way.
pub fn signature(secret: &[u8], timestamp: i64, delivery: Uuid, body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let Ok(mut mac) = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret) else {
        // HMAC takes a key of any length.
        return String::new();
    };
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(delivery.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("v1={hex}")
}

/// Turn a stored notice into the request to send. `delivery` is the notice's
/// id, the same on every attempt, so a receiver can drop a repeat.
/// `sequence` is the notice's place in the order they were written.
pub fn render(
    format: Format,
    delivery: Uuid,
    sequence: Option<i64>,
    payload: &Value,
    secret: Option<&str>,
    timestamp: i64,
) -> Rendered {
    match format {
        Format::Slack => Rendered {
            body: slack(payload).to_string().into_bytes(),
            headers: Vec::new(),
        },
        Format::Webhook => {
            let mut content = payload.clone();
            if let (Some(sequence), Some(object)) = (sequence, content.as_object_mut()) {
                object.insert("sequence".into(), json!(sequence));
            }
            let body = content.to_string().into_bytes();
            let event = payload
                .get("event")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let mut headers = vec![
                ("x-vda-event", event.to_owned()),
                ("x-vda-delivery", delivery.to_string()),
                ("x-vda-timestamp", timestamp.to_string()),
            ];
            if let Some(secret) = secret {
                headers.push((
                    "x-vda-signature",
                    signature(secret.as_bytes(), timestamp, delivery, &body),
                ));
            }
            Rendered { body, headers }
        }
    }
}

/// Characters that change the direction text is shown in. In a name they can
/// make it read as another name.
fn bidi(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}
/// A value from a person or an agent as one line of plain text, at most
/// `limit` characters: control characters and every kind of line break and
/// space become one space, runs of them collapse, direction marks are
/// dropped, and a value that is too long ends in an ellipsis. A value that
/// went through this cannot start a second line or reorder what follows it.
pub fn plain(text: &str, limit: usize) -> String {
    let mut line = String::with_capacity(text.len().min(limit * 4));
    let mut gap = false;
    for c in text.chars() {
        if bidi(c) {
            continue;
        }
        if c.is_control() || c.is_whitespace() {
            gap = true;
            continue;
        }
        if gap && !line.is_empty() {
            line.push(' ');
        }
        gap = false;
        line.push(c);
    }
    if line.chars().count() <= limit {
        return line;
    }
    let mut cut: String = line.chars().take(limit.saturating_sub(1)).collect();
    cut.truncate(cut.trim_end().len());
    cut.push('…');
    cut
}

/// Escape the three characters that Slack reads as control characters. An
/// escaped value cannot open a `<…>` form, so a name or a reason cannot make
/// a mention (`<!channel>`, `<@U…>`) or a link (`<https://…|text>`).
pub fn escape_slack(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            other => escaped.push(other),
        }
    }
    escaped
}
/// Cut escaped text to at most `limit` characters, on a character boundary
/// and never inside an entity: half of `&amp;` would show as something else.
fn fit(escaped: String, limit: usize) -> String {
    if escaped.chars().count() <= limit {
        return escaped;
    }
    let mut cut: String = escaped.chars().take(limit.saturating_sub(1)).collect();
    // In escaped text an `&` only ever starts an entity.
    if let Some(start) = cut.rfind('&') {
        if cut.get(start..).is_some_and(|tail| !tail.contains(';')) {
            cut.truncate(start);
        }
    }
    cut.push('…');
    cut
}

fn field<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}
/// One plain sentence about the event. Every value from the payload is made
/// one line and escaped here; nothing else puts a payload value into Slack
/// text.
fn sentence(payload: &Value) -> String {
    let event = field(payload, "event").unwrap_or_default();
    if event == TEST_EVENT {
        return "This is a test notice from the database gateway. Notices are set up correctly."
            .into();
    }
    let shown = |text: &str| escape_slack(&plain(text, NAME_LIMIT));
    let value = |key: &str| shown(field(payload, key).unwrap_or("unknown"));
    let who = match field(payload, "agent") {
        Some(agent) => format!("agent {} (owner {})", shown(agent), value("requester")),
        None => value("requester"),
    };
    let request = format!(
        "request for a write on {} ({}, {}) from {who}",
        value("cluster"),
        value("environment"),
        value("engine"),
    );
    match event {
        "approval.created" => format!("A new {request} waits for approval."),
        "approval.previewed" => format!("The {request} was previewed."),
        "approval.approved" => format!("The {request} was approved."),
        "approval.rejected" => format!("The {request} was rejected."),
        "approval.withdrawn" => format!("The {request} was withdrawn."),
        "approval.executed" => format!("The {request} was run."),
        "approval.failed" => match field(payload, "error_code") {
            Some("outcome_unknown") => {
                format!("Nobody knows whether the {request} ran (outcome_unknown).")
            }
            Some(code) => format!("The {request} failed when it ran ({}).", shown(code)),
            None => format!("The {request} failed when it ran."),
        },
        "approval.expired" => format!("The {request} expired before it ran."),
        _ => format!("The {request} changed."),
    }
}
/// The body of a Slack incoming webhook: a sentence, the link, and the
/// optional reason and row count on a second line.
pub fn slack(payload: &Value) -> Value {
    let link = field(payload, "url").map(|url| {
        let label = if field(payload, "event") == Some(TEST_EVENT) {
            "Open the console"
        } else {
            "Open the request"
        };
        format!(" <{}|{label}>", escape_slack(url))
    });
    // The sentence gives way, never the link: a cut link would not open.
    let room = SLACK_TEXT_LIMIT.saturating_sub(link.as_ref().map_or(0, |l| l.chars().count()));
    let mut text = fit(sentence(payload), room);
    text.push_str(link.as_deref().unwrap_or_default());
    // `verbatim` stops Slack from turning names and addresses inside the
    // text into links and mentions of its own.
    let mut blocks = vec![json!({
        "type": "section",
        "text": {"type": "mrkdwn", "text": text, "verbatim": true},
    })];
    let mut details = Vec::new();
    if let Some(rows) = payload.get("affected_rows").and_then(Value::as_i64) {
        details.push(format!("Rows: {rows}"));
    }
    if let Some(reason) = field(payload, "reason") {
        let reason = escape_slack(&plain(reason, super::REASON_LIMIT));
        details.push(fit(format!("Reason: {reason}"), SLACK_TEXT_LIMIT));
    }
    if !details.is_empty() {
        blocks.push(json!({
            "type": "context",
            "elements": details.iter().map(|detail| json!({
                "type": "mrkdwn", "text": detail, "verbatim": true,
            })).collect::<Vec<_>>(),
        }));
    }
    json!({"text": text, "blocks": blocks})
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_matches_a_known_answer() {
        // Computed with another tool:
        // printf '1800000000.00000000-0000-0000-0000-000000000005.{"version":1}' \
        //   | openssl dgst -sha256 -hmac 'vda_whsec_test'
        assert_eq!(
            signature(
                b"vda_whsec_test",
                1_800_000_000,
                Uuid::from_u128(5),
                br#"{"version":1}"#
            ),
            "v1=a8c6ab626df4e3c3fd38b9247b19a8e924bbbd7d9cdce676b00de093b19dcd5b"
        );
        // printf '1.00000000-0000-0000-0000-000000000000.' | openssl dgst -sha256 -hmac 'k'
        assert_eq!(
            signature(b"k", 1, Uuid::nil(), b""),
            "v1=16324081f644c4eb4135af85af96f51d3a2dd609b16ff2ae83bb0dff35156a9e"
        );
    }

    #[test]
    fn the_signature_covers_the_timestamp_the_delivery_the_body_and_the_secret() {
        let id = Uuid::from_u128(1);
        let signed = signature(b"secret", 10, id, b"body");
        assert_eq!(signed.len(), "v1=".len() + 64);
        assert_ne!(signed, signature(b"secret", 11, id, b"body"));
        assert_ne!(
            signed,
            signature(b"secret", 10, Uuid::from_u128(2), b"body")
        );
        assert_ne!(signed, signature(b"secret", 10, id, b"body."));
        assert_ne!(signed, signature(b"secret2", 10, id, b"body"));
        // The parts cannot be split another way: the timestamp is digits and
        // the delivery id has a fixed length and no dot.
        assert_ne!(
            signature(b"s", 1, id, b"0.x"),
            signature(b"s", 10, id, b".x")
        );
    }

    #[test]
    fn a_webhook_carries_the_payload_the_sequence_and_the_four_headers() {
        let delivery = Uuid::from_u128(5);
        let payload = json!({"version":1,"event":"approval.created","cluster":"orders"});
        let sent = render(
            Format::Webhook,
            delivery,
            Some(42),
            &payload,
            Some("s3cret"),
            1700,
        );
        let body: Value = serde_json::from_slice(&sent.body).unwrap_or_default();
        assert_eq!(
            body,
            json!({"version":1,"event":"approval.created","cluster":"orders","sequence":42})
        );
        let header = |name: &str| {
            sent.headers
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(header("x-vda-event").as_deref(), Some("approval.created"));
        assert_eq!(header("x-vda-delivery"), Some(delivery.to_string()));
        assert_eq!(header("x-vda-timestamp").as_deref(), Some("1700"));
        assert_eq!(
            header("x-vda-signature"),
            Some(signature(b"s3cret", 1700, delivery, &sent.body))
        );
        // The secret itself is never in what is sent.
        let all = format!("{:?}{}", sent.headers, String::from_utf8_lossy(&sent.body));
        assert!(!all.contains("s3cret"));
        // A test notice is about no request and has no place in the order.
        let test = render(Format::Webhook, delivery, None, &payload, Some("s"), 1);
        assert_eq!(test.body, payload.to_string().into_bytes());
    }

    #[test]
    fn a_value_becomes_one_plain_line() {
        assert_eq!(plain("orders", 10), "orders");
        assert_eq!(plain("  a \t b\r\n\nc  ", 10), "a b c");
        // A second line, forged.
        assert_eq!(
            plain(
                "line1\nThe request was approved by Security.\n> quoted",
                200
            ),
            "line1 The request was approved by Security. > quoted"
        );
        // Line and paragraph separators, next line, vertical tab, form feed.
        assert_eq!(
            plain("a\u{2028}b\u{2029}c\u{85}d\u{b}e\u{c}f", 20),
            "a b c d e f"
        );
        // Control characters: NUL, escape, bell, delete, C1.
        assert_eq!(
            plain("\0nul\u{1b}[31mansi \u{7}bel\u{7f}\u{9b}x", 40),
            "nul [31mansi bel x"
        );
        // Direction marks are dropped; what they hid is shown as written.
        assert_eq!(
            plain(
                "x\u{202e}txet desrever\u{202c} \u{200f}rtl\u{200e} \u{2066}iso\u{2069}\u{61c}",
                40
            ),
            "xtxet desrever rtl iso"
        );
        // Emoji that are made of joined parts stay whole.
        assert_eq!(
            plain("😀🏳\u{fe0f}\u{200d}🌈 👩🏽\u{200d}🚀", 40),
            "😀🏳\u{fe0f}\u{200d}🌈 👩🏽\u{200d}🚀"
        );
        // Cut on a character boundary, with an ellipsis, without a space before it.
        assert_eq!(plain(&"é".repeat(300), 200).chars().count(), 200);
        assert!(plain(&"é".repeat(300), 200).ends_with('…'));
        assert_eq!(plain("ab cd ef", 4), "ab…");
        assert_eq!(plain(&"é".repeat(200), 200), "é".repeat(200));
        assert_eq!(plain("", 5), "");
        assert_eq!(plain(" \n\t ", 5), "");
    }

    #[test]
    fn escaped_text_is_never_cut_inside_an_entity() {
        assert_eq!(fit("abc".into(), 3), "abc");
        assert_eq!(fit("abcd".into(), 3), "ab…");
        // Nine characters of room: `&amp;&am` would end inside an entity.
        assert_eq!(fit("&amp;&amp;&amp;".into(), 9), "&amp;…");
        assert_eq!(fit("&amp;&amp;&amp;".into(), 11), "&amp;&amp;…");
        assert_eq!(fit("&lt;&gt;&lt;".into(), 6), "&lt;…");
        assert_eq!(fit("ééé&amp;".into(), 5), "ééé…");
        for limit in 1..40 {
            let cut = fit(escape_slack(&"a&<>".repeat(20)), limit);
            assert!(cut.chars().count() <= limit, "{limit}: {cut}");
            let rest = cut
                .replace("&amp;", "")
                .replace("&lt;", "")
                .replace("&gt;", "");
            assert!(!rest.contains('&') && !rest.contains(';'), "{limit}: {cut}");
        }
    }

    #[test]
    fn slack_control_characters_are_escaped_in_every_value() {
        assert_eq!(escape_slack("a<b>&c"), "a&lt;b&gt;&amp;c");
        assert_eq!(escape_slack("&lt;"), "&amp;lt;");
        for hostile in [
            "<!channel> <!here> <!everyone> <@U123> <#C123> <!subteam^S1|sec> <https://evil.example|click>",
            "&lt;!channel&gt; &amp;lt;!here&amp;gt; &#60;!channel&#62; &#x3c;@U1&#x3e;",
            "\\u003c!channel\\u003e \\<!channel\\>",
            "\"}],\"text\":\"forged\",\"blocks\":[{\"type\":\"section\"",
        ] {
            let payload = json!({
                "version":1,"event":"approval.failed","cluster":hostile,"environment":hostile,
                "engine":hostile,"requester":hostile,"agent":hostile,"reason":hostile,
                "error_code":hostile,"affected_rows":4,
                "url":"https://gate.example/approvals?id=1&tab=all",
            });
            let body = slack(&payload);
            let section = body["blocks"][0]["text"]["text"].as_str().unwrap_or_default();
            // The only `<…>` form is the gateway's own link, at the end.
            assert_eq!(section.matches('<').count(), 1, "{section}");
            assert_eq!(section.matches('>').count(), 1, "{section}");
            assert!(section.ends_with(
                " <https://gate.example/approvals?id=1&amp;tab=all|Open the request>"
            ));
            assert_eq!(body["text"], json!(section));
            let reason = body["blocks"][1]["elements"][1]["text"].as_str().unwrap_or_default();
            assert!(!reason.contains('<') && !reason.contains('>'), "{reason}");
            // Every `&` that is left starts one of the three entities.
            let rest = format!("{section}{reason}")
                .replace("&amp;", "")
                .replace("&lt;", "")
                .replace("&gt;", "");
            assert!(!rest.contains('&'), "{rest}");
            // The body is one JSON document with the two expected keys.
            let parsed: Value = serde_json::from_str(&body.to_string()).unwrap_or_default();
            assert_eq!(parsed.as_object().map(|o| o.len()), Some(2));
            for block in body["blocks"].as_array().into_iter().flatten() {
                let texts = match block.get("elements").and_then(Value::as_array) {
                    Some(elements) => elements.clone(),
                    None => vec![block["text"].clone()],
                };
                for item in texts {
                    assert_eq!(item["type"], "mrkdwn");
                    assert_eq!(item["verbatim"], true);
                }
            }
        }
    }

    #[test]
    fn a_name_or_a_reason_cannot_add_a_line_or_reorder_the_sentence() {
        let forged = "line1\nThe request was approved by Security.\n> quoted\n&gt; quoted2";
        let marks = "x\u{202e}txet desrever\u{202c} \u{200f}rtl\u{200e} \u{2066}iso\u{2069}";
        let controls = "emoji 😀 \0nul\u{1b}[31mansi \u{7}bel\u{2028}sep\u{2029}par";
        for hostile in [forged, marks, controls] {
            let payload = json!({
                "event":"approval.failed","cluster":hostile,"environment":hostile,
                "engine":hostile,"requester":hostile,"agent":hostile,"reason":hostile,
                "error_code":hostile,
            });
            let text = slack(&payload).to_string();
            let shown: Value = serde_json::from_str(&text).unwrap_or_default();
            for part in [
                shown["text"].as_str().unwrap_or_default(),
                shown["blocks"][1]["elements"][0]["text"]
                    .as_str()
                    .unwrap_or_default(),
            ] {
                assert!(!part.is_empty());
                assert!(
                    !part
                        .chars()
                        .any(|c| c.is_control() || bidi(c) || matches!(c, '\u{2028}' | '\u{2029}')),
                    "{part:?}"
                );
                assert!(!part.contains("  "), "{part:?}");
            }
        }
        let said = slack(
            &json!({"event":"approval.rejected","cluster":"c","environment":"e",
            "engine":"postgres","requester":forged}),
        );
        assert_eq!(
            said["text"],
            "The request for a write on c (e, postgres) from line1 The request was approved by \
             Security. &gt; quoted &amp;gt; quoted2 was rejected."
        );
    }

    #[test]
    fn the_longest_values_stay_under_the_limit_of_a_slack_section() {
        for fill in ["&", "<", "a", "😀", "é"] {
            let name = fill.repeat(256);
            let reason = fill.repeat(10_000);
            let payload = json!({
                "event":"approval.failed","cluster":name,"environment":name,"engine":name,
                "requester":name,"agent":name,"reason":reason,"error_code":name,
                "affected_rows":7,
                "url":"https://gate.example/approvals?id=00000000-0000-0000-0000-000000000000&tab=all",
            });
            let body = slack(&payload);
            let section = body["blocks"][0]["text"]["text"]
                .as_str()
                .unwrap_or_default();
            assert!(
                section.chars().count() <= 3000,
                "{fill}: {}",
                section.chars().count()
            );
            assert!(body["text"].as_str().unwrap_or_default().chars().count() <= 3000);
            // The link is whole, whatever was cut before it.
            assert!(
                section.ends_with("&amp;tab=all|Open the request>"),
                "{fill}"
            );
            let reason = body["blocks"][1]["elements"][1]["text"]
                .as_str()
                .unwrap_or_default();
            assert!(
                reason.chars().count() <= 3000,
                "{fill}: {}",
                reason.chars().count()
            );
            for part in [section, reason] {
                let rest = part
                    .replace("&amp;", "")
                    .replace("&lt;", "")
                    .replace("&gt;", "");
                assert!(!rest.contains('&'), "{fill}: cut inside an entity");
            }
        }
    }

    #[test]
    fn slack_says_what_happened_in_one_sentence() {
        let base = json!({"cluster":"orders","environment":"production","engine":"postgres",
            "requester":"Ada"});
        let say = |event: &str, extra: Value| {
            let mut payload = base.clone();
            if let (Some(object), Some(more)) = (payload.as_object_mut(), extra.as_object()) {
                object.insert("event".into(), json!(event));
                object.extend(more.clone());
            }
            slack(&payload)["text"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(
            say("approval.created", json!({})),
            "A new request for a write on orders (production, postgres) from Ada waits for approval."
        );
        assert_eq!(
            say("approval.executed", json!({"agent":"bot"})),
            "The request for a write on orders (production, postgres) from agent bot (owner Ada) was run."
        );
        assert!(
            say("approval.failed", json!({"error_code":"effect_changed"}))
                .ends_with("failed when it ran (effect_changed).")
        );
        assert!(
            say("approval.failed", json!({"error_code":"outcome_unknown"}))
                .starts_with("Nobody knows whether")
        );
        assert!(say("approval.expired", json!({})).ends_with("expired before it ran."));
        // Without the switches there is one block, and no reason or count.
        let plain = slack(&json!({"event":"approval.created","cluster":"orders"}));
        assert_eq!(plain["blocks"].as_array().map(Vec::len), Some(1));
        let test = slack(&json!({"event":TEST_EVENT,"url":"https://gate.example"}));
        assert!(test["text"]
            .as_str()
            .unwrap_or_default()
            .ends_with("<https://gate.example|Open the console>"));
    }

    #[test]
    fn a_slack_body_has_no_signature_headers_and_no_sequence() {
        let sent = render(
            Format::Slack,
            Uuid::nil(),
            Some(9),
            &json!({"event":"approval.created"}),
            Some("s3cret"),
            1,
        );
        assert!(sent.headers.is_empty());
        let body: Value = serde_json::from_slice(&sent.body).unwrap_or_default();
        assert!(body["text"].is_string() && body["blocks"].is_array());
        assert!(!String::from_utf8_lossy(&sent.body).contains("sequence"));
    }
}
