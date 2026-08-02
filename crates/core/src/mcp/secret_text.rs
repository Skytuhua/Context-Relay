use context_relay_protocol::{ClientError, ErrorCode};

const PRIVATE_KEY_MARKERS: [&str; 2] = [
    "-----begin private key-----",
    "-----begin openssh private key-----",
];
const SENSITIVE_KEYS: [&str; 8] = [
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "credential",
];
const TOKEN_PREFIXES: [&str; 7] = [
    "sk-",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
];

pub fn reject_secret_like(text: &str) -> Result<(), ClientError> {
    if contains_secret_like(text) {
        return Err(ClientError {
            code: ErrorCode::InvalidRequest,
            message: "The handoff contains secret-like text".to_owned(),
            field_path: None,
            retryable: false,
        });
    }
    Ok(())
}

pub(crate) fn contains_secret_like(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    PRIVATE_KEY_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
        || has_sensitive_assignment(&lower)
        || has_bounded_token_shape(text)
}

fn has_sensitive_assignment(lower: &str) -> bool {
    lower.lines().any(|line| {
        SENSITIVE_KEYS.iter().any(|key| {
            line.match_indices(key).any(|(start, _)| {
                let before = line[..start].chars().next_back();
                if before
                    .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    return false;
                }
                let suffix = &line[start + key.len()..];
                let after = suffix.chars().next();
                if after
                    .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    return false;
                }
                let mut separator_text = suffix.trim_start();
                if let Some(stripped) = separator_text.strip_prefix(['"', '\'']) {
                    separator_text = stripped.trim_start();
                }
                let Some(rhs) = separator_text
                    .strip_prefix(':')
                    .or_else(|| separator_text.strip_prefix('='))
                else {
                    return false;
                };
                sensitive_rhs(rhs)
            })
        })
    })
}

fn sensitive_rhs(rhs: &str) -> bool {
    let mut value = rhs.trim();
    if value.is_empty() || value.starts_with('#') {
        return false;
    }
    value = value.trim_end_matches(',').trim_end();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(bytes[0], b'"' | b'\'') && bytes.last() == Some(&bytes[0]) {
            value = value[1..value.len() - 1].trim();
        }
    }
    if let Some((before_comment, _)) = value.split_once(" #") {
        value = before_comment.trim_end();
    }
    if value.is_empty() || benign_sensitive_placeholder(value) {
        return false;
    }
    true
}

fn benign_sensitive_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if matches!(lower.as_str(), "<provided by environment>" | "[redacted]") {
        return true;
    }
    let Some(environment) = value
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    else {
        return false;
    };
    !environment.is_empty()
        && environment.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

fn has_bounded_token_shape(text: &str) -> bool {
    let whitespace_delimited = text
        .split(|character: char| character.is_whitespace() || matches!(character, '"' | '\''))
        .map(|token| {
            token.trim_matches(|character: char| {
                character.is_ascii_punctuation() && !matches!(character, '-' | '_')
            })
        });
    let syntax_delimited = text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    });
    whitespace_delimited
        .chain(syntax_delimited)
        .filter(|token| (8..=512).contains(&token.len()))
        .any(|token| {
            let lower = token.to_ascii_lowercase();
            TOKEN_PREFIXES
                .iter()
                .any(|prefix| lower.starts_with(prefix) && token.len() >= prefix.len() + 12)
                || looks_like_aws_access_key(token)
                || looks_like_jwt(token)
        })
}

fn looks_like_aws_access_key(token: &str) -> bool {
    token.len() == 20
        && token.starts_with("AKIA")
        && token[4..]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn looks_like_jwt(token: &str) -> bool {
    let mut segments = token.split('.');
    let Some(header) = segments.next() else {
        return false;
    };
    let Some(payload) = segments.next() else {
        return false;
    };
    let Some(signature) = segments.next() else {
        return false;
    };
    segments.next().is_none()
        && (8..=512).contains(&header.len())
        && (8..=4_096).contains(&payload.len())
        && (8..=512).contains(&signature.len())
        && [header, payload, signature].into_iter().all(is_base64url)
}

fn is_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_environment_and_redacted_sensitive_assignments_are_documentation() {
        for separator in ['=', ':'] {
            for rhs in [
                "",
                "# intentionally unset",
                "<provided by environment>",
                "${ENV_VAR}",
                "[redacted]",
            ] {
                let text = format!("api_key {separator} {rhs}");
                assert!(!contains_secret_like(&text), "{text}");
            }
        }

        for text in [
            "api_key = actual-secret-value",
            "password: correct-horse-battery-staple",
            "Authorization: Bearer must-not-echo",
            "access_token = abc12345",
        ] {
            assert!(contains_secret_like(text), "{text}");
        }
    }

    #[test]
    fn short_nonempty_sensitive_assignments_are_secret_like() {
        for text in [
            "password = abc123",
            "api_key = abcdefg",
            "password = \"abc123\"",
            "api_key: 'abcdefg'",
        ] {
            assert!(contains_secret_like(text), "{text}");
        }
    }

    #[test]
    fn rendered_markdown_delimiters_do_not_hide_bounded_token_shapes() {
        for token in [
            "`sk-abcdefghijkl`",
            "**(ghp_abcdefghijkl),**",
            "<xoxb-abcdefghijkl>",
            "[AKIA1234567890ABCDEF]",
            "{abcdefgh.ijklmnop.qrstuvwx};",
        ] {
            let rendered = format!("# Handoff\n\n## Summary\n\nKeep {token} out.");
            let error = reject_secret_like(&rendered).unwrap_err();

            assert_eq!(error.code, ErrorCode::InvalidRequest, "{token}");
            assert_eq!(error.message, "The handoff contains secret-like text");
            assert!(error.field_path.is_none());
            assert!(!error.retryable);
            assert!(!error.message.contains(token));
        }
    }
}
