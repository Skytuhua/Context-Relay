fn validate(project: Option<&str>, key: Option<&str>) -> Result<(), &'static str> {
    match (project, key) {
        (None, None) => Ok(()),
        (Some(project), Some(key)) => {
            if project.is_empty() || project.trim() != project {
                return Err(
                    "Hosted project URL must be nonempty and have no surrounding whitespace",
                );
            }
            let suffix = key.strip_prefix("sb_publishable_").ok_or(
                "Desktop hosted authentication requires a publishable key; secret and legacy JWT keys are forbidden",
            )?;
            if suffix.is_empty()
                || key.len() > 4096
                || !suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err("Invalid hosted publishable key");
            }
            Ok(())
        }
        _ => Err(
            "Set both CONTEXT_RELAY_HOSTED_URL and CONTEXT_RELAY_HOSTED_PUBLISHABLE_KEY, or neither",
        ),
    }
}

#[cfg(not(test))]
fn main() {
    println!("cargo:rerun-if-env-changed=CONTEXT_RELAY_HOSTED_URL");
    println!("cargo:rerun-if-env-changed=CONTEXT_RELAY_HOSTED_PUBLISHABLE_KEY");
    let project = std::env::var("CONTEXT_RELAY_HOSTED_URL");
    let key = std::env::var("CONTEXT_RELAY_HOSTED_PUBLISHABLE_KEY");
    for value in [&project, &key] {
        assert!(
            !matches!(value, Err(std::env::VarError::NotUnicode(_))),
            "Hosted configuration must be Unicode"
        );
    }
    if let Err(message) = validate(project.as_deref().ok(), key.as_deref().ok()) {
        panic!("{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::validate;

    #[test]
    fn only_complete_public_configuration_is_accepted() {
        assert!(validate(None, None).is_ok());
        let url = Some("https://example.supabase.co");
        assert!(validate(url, Some("sb_publishable_test-123_ABC")).is_ok());
        assert!(validate(url, None).is_err());
        assert!(validate(None, Some("sb_publishable_test")).is_err());
        for key in [
            "sb_secret_test",
            "eyJhbGciOiJIUzI1NiJ9.payload.signature",
            "",
            "sb_publishable_",
            "sb_publishable_a\n",
            "sb_publishable_a b",
        ] {
            assert!(validate(url, Some(key)).is_err());
        }
        assert!(validate(Some(" "), Some("sb_publishable_test")).is_err());
    }
}
