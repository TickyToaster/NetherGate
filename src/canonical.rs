//! ECMA-262 `JSON.stringify`-compatible serialization for signed payloads.
//!
//! Do not use `serde_json` here. Signed payload layouts need exact string
//! escaping, raw non-ASCII UTF-8 output, and integer formatting.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    String(String),
    Unsigned(u64),
    Array(Vec<Value>),
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

pub fn stringify(value: &Value) -> String {
    let mut output = String::new();
    write_value(&mut output, value);
    output
}

pub fn join_array(parts: &[Value]) -> String {
    stringify(&Value::Array(parts.to_vec()))
}

fn write_value(output: &mut String, value: &Value) {
    match value {
        Value::String(value) => write_string(output, value),
        Value::Unsigned(value) => output.push_str(&value.to_string()),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_value(output, value);
            }
            output.push(']');
        }
    }
}

fn write_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_stringify_for_mixed_arrays() {
        assert_eq!(
            join_array(&[
                "protocol".into(),
                "caf\u{e9} \u{1f98a} \"<proxy>\"\n".into(),
                1788484800000u64.into(),
                Value::Array(vec!["a".into(), 17u64.into()]),
            ]),
            "[\"protocol\",\"caf\u{e9} \u{1f98a} \\\"<proxy>\\\"\\n\",1788484800000,[\"a\",17]]"
        );
    }

    #[test]
    fn escapes_controls_with_lowercase_hex() {
        assert_eq!(
            stringify(&Value::from("\u{0000}\u{001f}")),
            "\"\\u0000\\u001f\""
        );
    }
}
