//! Shared rejection of control characters before parsing or persistence.
use crate::error::ApiError;
use serde_json::Value;

/// Allow ordinary text and tab/newline/carriage return, rejecting NUL and other C0 controls.
pub fn text(value: &str) -> Result<(), ApiError> {
    if value
        .chars()
        .any(|c| c < ' ' && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err(ApiError::validation(
            "Text contains prohibited control characters",
        ));
    }
    Ok(())
}

/// Characters that are invisible, blank, or reorder text. In a name or a note
/// they would let two different texts look the same to a person. The list
/// covers format and filler characters, variation selectors, tags, and every
/// whitespace character other than the plain space.
fn deceptive(c: char) -> bool {
    (c.is_whitespace() && c != ' ')
        || matches!(c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}'
            | '\u{17B5}' | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{2800}' | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}' | '\u{FFF0}'..='\u{FFFB}'
            | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}')
}
/// Whether a single line of text shows everything it contains. Joiners and
/// the emoji selector are part of real words and emoji, but only after a
/// non-ASCII character; after plain text they hide a difference.
pub fn shows_all(value: &str) -> bool {
    let mut previous = ' ';
    !value.chars().any(|c| {
        let joins = matches!(c, '\u{200C}' | '\u{200D}' | '\u{FE0F}')
            && !previous.is_ascii()
            && !deceptive(previous);
        previous = c;
        deceptive(c) && !joins
    })
}

/// Validate every JSON string, including object keys (such as tag names).
pub fn json(value: &Value) -> Result<(), ApiError> {
    match value {
        Value::String(value) => text(value),
        Value::Array(values) => values.iter().try_for_each(json),
        Value::Object(values) => values.iter().try_for_each(|(key, value)| {
            text(key)?;
            json(value)
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_controls_in_nested_text_and_keys() {
        for c in (0..32).filter(|c| !matches!(c, 9 | 10 | 13)) {
            assert!(text(&format!("a{}b", char::from(c))).is_err());
        }
        assert!(text("a\tb\nc\rλ").is_ok());
        assert!(json(&serde_json::json!({"tags":{"bad\u{0}":"value"}})).is_err());
        assert!(json(&serde_json::json!({"note":["bad\u{1}"]})).is_err());
    }
}
