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
    let lower = text.to_ascii_lowercase();
    if PRIVATE_KEY_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
        || has_sensitive_assignment(&lower)
        || has_bounded_token_shape(text)
    {
        return Err(ClientError {
            code: ErrorCode::InvalidRequest,
            message: "The handoff contains secret-like text".to_owned(),
            field_path: None,
            retryable: false,
        });
    }
    Ok(())
}

fn has_sensitive_assignment(lower: &str) -> bool {
    SENSITIVE_KEYS.iter().any(|key| {
        lower.match_indices(key).any(|(start, _)| {
            let before = lower[..start].chars().next_back();
            if before.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                return false;
            }
            let mut suffix = lower[start + key.len()..].chars();
            let after = suffix.next();
            if after.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
            {
                return false;
            }
            let mut separator_text = lower[start + key.len()..].trim_start();
            if let Some(stripped) = separator_text.strip_prefix(['"', '\'']) {
                separator_text = stripped.trim_start();
            }
            separator_text.starts_with(':') || separator_text.starts_with('=')
        })
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
