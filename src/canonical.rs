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
    let mut temp = String::new();
    let x = value;
    if let Value::String(s) = x {
        temp.push('"');
        let mut i = 0;
        let chars: Vec<char> = s.chars().collect();
        while i < chars.len() {
            let c = chars[i];
            if c == '"' {
                temp.push_str("\\\"");
            } else if c == '\\' {
                temp.push_str("\\\\");
            } else if c == '\n' {
                temp.push_str("\\n");
            } else if c == '\r' {
                temp.push_str("\\r");
            } else if c == '\t' {
                temp.push_str("\\t");
            } else if c == '\u{8}' {
                temp.push_str("\\b");
            } else if c == '\u{c}' {
                temp.push_str("\\f");
            } else if (c as u32) < 32 {
                let n = c as u32;
                temp.push_str("\\u");
                if n < 16 {
                    temp.push_str("000");
                } else if n < 256 {
                    temp.push_str("00");
                } else if n < 4096 {
                    temp.push('0');
                }
                temp.push_str(&format!("{:x}", n));
            } else {
                temp.push(c);
            }
            i += 1;
        }
        temp.push('"');
    } else if let Value::Unsigned(n) = x {
        temp.push_str(&n.to_string());
    } else if let Value::Array(a) = x {
        temp.push('[');
        let mut i = 0;
        while i < a.len() {
            if i > 0 {
                temp.push(',');
            }
            let b = &a[i];
            if let Value::String(s) = b {
                temp.push('"');
                let mut j = 0;
                let chars: Vec<char> = s.chars().collect();
                while j < chars.len() {
                    let c = chars[j];
                    if c == '"' {
                        temp.push_str("\\\"");
                    } else if c == '\\' {
                        temp.push_str("\\\\");
                    } else if c == '\n' {
                        temp.push_str("\\n");
                    } else if c == '\r' {
                        temp.push_str("\\r");
                    } else if c == '\t' {
                        temp.push_str("\\t");
                    } else if c == '\u{8}' {
                        temp.push_str("\\b");
                    } else if c == '\u{c}' {
                        temp.push_str("\\f");
                    } else if (c as u32) < 32 {
                        let n = c as u32;
                        temp.push_str("\\u");
                        if n < 16 {
                            temp.push_str("000");
                        } else if n < 256 {
                            temp.push_str("00");
                        } else if n < 4096 {
                            temp.push('0');
                        }
                        temp.push_str(&format!("{:x}", n));
                    } else {
                        temp.push(c);
                    }
                    j += 1;
                }
                temp.push('"');
            } else if let Value::Unsigned(n) = b {
                temp.push_str(&n.to_string());
            } else if let Value::Array(c) = b {
                temp.push_str(&join_array(c));
            }
            i += 1;
        }
        temp.push(']');
    }
    temp
}

pub fn join_array(parts: &[Value]) -> String {
    let mut x = String::new();
    x.push('[');
    let mut i = 0;
    while i < parts.len() {
        if i > 0 {
            x.push(',');
        }
        let temp = &parts[i];
        x.push_str(&stringify(temp));
        i += 1;
    }
    x.push(']');
    x
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
