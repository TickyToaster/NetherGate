//! Canonical provider origins.
//!
//! This is an intentionally narrow ASCII profile. It never normalizes signed
//! input: a string either is already canonical or it is rejected.

const MAX_ORIGIN_LEN: usize = 267;
const MAX_DNS_LEN: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OriginError {
    #[error("origin is not canonical")]
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Https,
    Http,
}

impl Origin {
    pub fn parse(input: &str) -> Result<Self, OriginError> {
        if input.len() > MAX_ORIGIN_LEN || !input.is_ascii() {
            return Err(OriginError::Invalid);
        }

        let (scheme, rest) = if let Some(rest) = input.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = input.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else {
            return Err(OriginError::Invalid);
        };

        if rest.is_empty()
            || !rest.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
            })
        {
            return Err(OriginError::Invalid);
        }

        let (host, port) = split_host_port(rest)?;
        let canonical_host = canonical_host(host)?;
        let port = port.map(parse_port).transpose()?;

        match scheme {
            Scheme::Https => {
                if port == Some(443) {
                    return Err(OriginError::Invalid);
                }
            }
            Scheme::Http => {
                if !matches!(canonical_host.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
                    return Err(OriginError::Invalid);
                }
                if port == Some(80) {
                    return Err(OriginError::Invalid);
                }
            }
        }

        let mut canonical = String::from(match scheme {
            Scheme::Https => "https://",
            Scheme::Http => "http://",
        });
        canonical.push_str(&canonical_host);
        if let Some(port) = port {
            canonical.push(':');
            canonical.push_str(&port.to_string());
        }

        if canonical != input {
            return Err(OriginError::Invalid);
        }

        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn split_host_port(rest: &str) -> Result<(&str, Option<&str>), OriginError> {
    if let Some(after_bracket) = rest.strip_prefix('[') {
        let close = after_bracket.find(']').ok_or(OriginError::Invalid)?;
        let host = &rest[..close + 2];
        let tail = &after_bracket[close + 1..];
        let port = if tail.is_empty() {
            None
        } else if let Some(port) = tail.strip_prefix(':') {
            if port.is_empty() {
                return Err(OriginError::Invalid);
            }
            Some(port)
        } else {
            return Err(OriginError::Invalid);
        };
        return Ok((host, port));
    }

    if let Some((host, port)) = rest.split_once(':') {
        if host.is_empty() || port.is_empty() || port.contains(':') {
            return Err(OriginError::Invalid);
        }
        Ok((host, Some(port)))
    } else {
        if rest.is_empty() {
            return Err(OriginError::Invalid);
        }
        Ok((rest, None))
    }
}

fn parse_port(input: &str) -> Result<u16, OriginError> {
    if input.is_empty()
        || !input.bytes().all(|byte| byte.is_ascii_digit())
        || (input.len() > 1 && input.starts_with('0'))
    {
        return Err(OriginError::Invalid);
    }
    let port: u32 = input.parse().map_err(|_| OriginError::Invalid)?;
    if !(1..=65535).contains(&port) {
        return Err(OriginError::Invalid);
    }
    Ok(port as u16)
}

fn canonical_host(host: &str) -> Result<String, OriginError> {
    if let Some(inner) = host.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or(OriginError::Invalid)?;
        let canonical = canonical_ipv6(inner)?;
        return Ok(format!("[{canonical}]"));
    }

    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        return canonical_ipv4(&parts);
    }

    canonical_dns(host)
}

fn canonical_ipv4(parts: &[&str]) -> Result<String, OriginError> {
    if parts.len() != 4 {
        return Err(OriginError::Invalid);
    }
    let mut octets = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(OriginError::Invalid);
        }
        let value: u16 = part.parse().map_err(|_| OriginError::Invalid)?;
        if value > 255 {
            return Err(OriginError::Invalid);
        }
        octets[index] = value as u8;
    }
    Ok(format!(
        "{}.{}.{}.{}",
        octets[0], octets[1], octets[2], octets[3]
    ))
}

fn canonical_dns(host: &str) -> Result<String, OriginError> {
    if host.is_empty() || host.len() > MAX_DNS_LEN || host.ends_with('.') {
        return Err(OriginError::Invalid);
    }

    let labels: Vec<&str> = host.split('.').collect();
    for (index, label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 63 {
            return Err(OriginError::Invalid);
        }
        if label.starts_with("xn--") {
            return Err(OriginError::Invalid);
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return Err(OriginError::Invalid);
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(OriginError::Invalid);
        }
        if index == labels.len() - 1 && !bytes[0].is_ascii_lowercase() {
            return Err(OriginError::Invalid);
        }
    }

    Ok(host.to_owned())
}

fn canonical_ipv6(input: &str) -> Result<String, OriginError> {
    if input.is_empty() || input.contains('.') || input.contains('%') {
        return Err(OriginError::Invalid);
    }

    let pieces = if let Some((left, right)) = input.split_once("::") {
        if right.contains("::") {
            return Err(OriginError::Invalid);
        }
        let left = parse_ipv6_pieces(left)?;
        let right = parse_ipv6_pieces(right)?;
        if left.len() + right.len() >= 8 {
            return Err(OriginError::Invalid);
        }
        let omitted = 8 - left.len() - right.len();
        if omitted < 2 {
            return Err(OriginError::Invalid);
        }
        let mut pieces = left;
        pieces.extend(std::iter::repeat_n(0u16, omitted));
        pieces.extend(right);
        pieces
    } else {
        let pieces = parse_ipv6_pieces(input)?;
        if pieces.len() != 8 {
            return Err(OriginError::Invalid);
        }
        pieces
    };

    let mut best_start = 0;
    let mut best_len = 0;
    let mut index = 0;
    while index < pieces.len() {
        if pieces[index] == 0 {
            let start = index;
            while index < pieces.len() && pieces[index] == 0 {
                index += 1;
            }
            let len = index - start;
            if len > best_len {
                best_start = start;
                best_len = len;
            }
        } else {
            index += 1;
        }
    }

    let mut output = String::new();
    let mut index = 0;
    while index < pieces.len() {
        if best_len >= 2 && index == best_start {
            output.push_str("::");
            index += best_len;
            continue;
        }
        if !output.is_empty() && !output.ends_with(':') {
            output.push(':');
        }
        output.push_str(&format!("{:x}", pieces[index]));
        index += 1;
    }
    Ok(output)
}

fn parse_ipv6_pieces(input: &str) -> Result<Vec<u16>, OriginError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    input
        .split(':')
        .map(|piece| {
            if piece.is_empty()
                || piece.len() > 4
                || (piece.len() > 1 && piece.starts_with('0'))
                || !piece
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(OriginError::Invalid);
            }
            u16::from_str_radix(piece, 16).map_err(|_| OriginError::Invalid)
        })
        .collect()
}
