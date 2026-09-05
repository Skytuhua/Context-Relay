use context_relay_protocol::{ClientError, ErrorCode};

const PRIVATE_KEY_PREFIX: &str = "-----begin ";
const PRIVATE_KEY_MARKER_PARTS: [(&str, &str); 7] = [
    ("private", " key-----"),
    ("encrypted private", " key-----"),
    ("rsa private", " key-----"),
    ("ec private", " key-----"),
    ("dsa private", " key-----"),
    ("openssh private", " key-----"),
    ("pgp private", " key block-----"),
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
const TOKEN_PREFIXES: [&str; 26] = [
    "sk-",
    "sk_live_",
    "rk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "xapp-",
    "xoxe-",
    "npm_",
    "pypi-",
    "ya29.",
    "aiza",
    "hf_",
    "sg.",
    "mfa.",
    "dop_v1_",
    "lin_api_",
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
    contains_private_key_marker(&lower)
        || has_sensitive_assignment(&lower)
        || has_bearer_token(text)
        || has_bounded_token_shape(text)
}

fn contains_private_key_marker(lower: &str) -> bool {
    lower
        .match_indices(PRIVATE_KEY_PREFIX)
        .map(|(start, _)| &lower[start + PRIVATE_KEY_PREFIX.len()..])
        .any(|suffix| {
            PRIVATE_KEY_MARKER_PARTS.iter().any(|(label, end)| {
                suffix
                    .strip_prefix(label)
                    .is_some_and(|suffix| suffix.starts_with(end))
            })
        })
}

fn has_bearer_token(text: &str) -> bool {
    let words = text.split_whitespace().collect::<Vec<_>>();
    words.windows(2).any(|pair| {
        pair[0]
            .trim_matches(|character: char| character.is_ascii_punctuation())
            .eq_ignore_ascii_case("bearer")
            && {
                let original = pair[1];
                let value =
                    original.trim_matches(|character: char| character.is_ascii_punctuation());
                (16..=512).contains(&value.len())
                    && !benign_sensitive_placeholder(original)
                    && !benign_sensitive_placeholder(value)
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'+' | b'/')
                    })
            }
    })
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
    let mut words = value.split_whitespace();
    if words
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("bearer"))
        && let Some(token) = words.next()
        && words.next().is_none()
    {
        return benign_sensitive_placeholder(token);
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
        && (token.starts_with("AKIA") || token.starts_with("ASIA"))
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
    fn bearer_environment_placeholder_is_documentation() {
        for text in [
            "Bearer ${CONTEXT_RELAY_ACCESS_TOKEN}",
            "Authorization: Bearer ${CONTEXT_RELAY_ACCESS_TOKEN}",
        ] {
            assert!(!contains_secret_like(text), "{text}");
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

    #[test]
    fn all_common_private_key_pem_headers_are_secret_like() {
        for (kind, block) in [
            ("RSA", false),
            ("EC", false),
            ("DSA", false),
            ("ENCRYPTED", false),
            ("PGP", true),
        ] {
            let mut marker = ["-----BEGIN", kind, "PRIVATE", "KEY"].join(" ");
            if block {
                marker.push_str(" BLOCK");
            }
            marker.push_str("-----");
            assert!(contains_secret_like(&marker), "{marker}");
        }
    }

    #[test]
    fn common_bearer_and_provider_token_families_are_secret_like() {
        let gitlab_token = ["gl", "pat-abcdefghijklmnopqrst"].concat();
        let stripe_secret = ["sk", "_live_abcdefghijklmnopqrstuvwxyz012345"].concat();
        let stripe_restricted = ["rk", "_live_abcdefghijklmnopqrstuvwxyz012345"].concat();
        for token in [
            "Bearer abcdefghijklmnopqrstuvwxyz012345",
            gitlab_token.as_str(),
            "npm_abcdefghijklmnopqrstuvwxyz012345",
            "pypi-AgEIcHlwaS5vcmcCJGFiY2RlZmdoaWprbG1ub3BxcnN0",
            "ya29.abcdefghijklmnopqrstuvwxyz012345",
            "AIzaSyAabcdefghijklmnopqrstuvwxyz012345",
            "gho_abcdefghijklmnopqrstuvwxyz0123456789",
            "xapp-1-abcdefghijklmnopqrstuvwxyz0123456789",
            "xoxs-abcdefghijklmnopqrstuvwxyz0123456789",
            stripe_secret.as_str(),
            stripe_restricted.as_str(),
            "ASIA1234567890ABCDEF",
            "SG.abcdefghijklmnop.qrstuvwxyz012345",
        ] {
            assert!(contains_secret_like(token), "{token}");
        }
    }
}
