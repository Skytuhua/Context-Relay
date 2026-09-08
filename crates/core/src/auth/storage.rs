use std::fmt;

use keyring::Entry;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    HostedIdentity, LoginError,
    transport::{canonical_uuid, secret},
};
use crate::sync::supabase::{valid_header_secret, validated_project_url};

/// Unverified restart material, never a substitute for a verified HostedSession.
pub struct StoredLogin {
    pub(super) project: Url,
    pub(super) identity: HostedIdentity,
    pub(super) refresh_token: Zeroizing<String>,
}

impl fmt::Debug for StoredLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredLogin([REDACTED])")
    }
}

impl StoredLogin {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, LoginError> {
        #[derive(Serialize)]
        struct Record<'a> {
            version: u8,
            project: &'a str,
            user_id: String,
            session_id: String,
            refresh_token: &'a str,
        }
        let bytes = serde_json::to_vec(&Record {
            version: 1,
            project: self.project.as_str(),
            user_id: self.identity.user_id.to_string(),
            session_id: self.identity.session_id.to_string(),
            refresh_token: &self.refresh_token,
        })
        .map(Zeroizing::new)
        .map_err(|_| LoginError::CredentialStore)?;
        if bytes.len() > 8192 {
            return Err(LoginError::CredentialStore);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], project: &Url) -> Result<Self, LoginError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Record {
            version: u8,
            project: String,
            user_id: String,
            session_id: String,
            #[serde(deserialize_with = "secret")]
            refresh_token: Zeroizing<String>,
        }
        if bytes.len() > 8192 {
            return Err(LoginError::CredentialStore);
        }
        let record: Record =
            serde_json::from_slice(bytes).map_err(|_| LoginError::CredentialStore)?;
        if record.version != 1
            || record.project != project.as_str()
            || !valid_header_secret(&record.refresh_token)
            || record.refresh_token.len() > 4096
        {
            return Err(LoginError::CredentialStore);
        }
        Ok(Self {
            project: project.clone(),
            identity: HostedIdentity {
                user_id: canonical_uuid(&record.user_id)
                    .map_err(|_| LoginError::CredentialStore)?,
                session_id: canonical_uuid(&record.session_id)
                    .map_err(|_| LoginError::CredentialStore)?,
            },
            refresh_token: record.refresh_token,
        })
    }
}

/// One daemon-owned login slot per local profile and hosted project.
/// The owner serializes save/clear with login, refresh and logout.
pub struct PlatformLoginStore {
    project: Url,
    entry: Entry,
}

impl PlatformLoginStore {
    pub fn new(project: &str, profile: &str) -> Result<Self, LoginError> {
        let project = validated_project_url(project).map_err(|_| LoginError::Configuration)?;
        if profile.is_empty()
            || profile.len() > 128
            || !profile.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(LoginError::Configuration);
        }
        let mut digest = Sha256::new();
        digest.update(project.as_str());
        digest.update([0]);
        digest.update(profile);
        let name = format!("{:x}", digest.finalize());
        let entry = Entry::new("context-relay-hosted-login", &name)
            .map_err(|_| LoginError::CredentialStore)?;
        Ok(Self { project, entry })
    }

    pub fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
        match self.entry.get_secret() {
            Ok(bytes) => StoredLogin::decode(&Zeroizing::new(bytes), &self.project).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(LoginError::CredentialStore),
        }
    }

    pub fn save(&self, login: &StoredLogin) -> Result<(), LoginError> {
        if login.project != self.project {
            return Err(LoginError::Configuration);
        }
        let bytes = login.encode()?;
        self.entry
            .set_secret(&bytes)
            .map_err(|_| LoginError::CredentialStore)
    }

    pub fn clear(&self) -> Result<(), LoginError> {
        match self.entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(LoginError::CredentialStore),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "writes and removes a uniquely named synthetic OS credential"]
    fn platform_login_roundtrip_and_clear() {
        use rand_core::RngCore;
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let profile = format!("qualification-{:x}", u128::from_be_bytes(nonce));
        let project = "https://qualification.invalid/";
        let store = PlatformLoginStore::new(project, &profile).unwrap();
        let login = StoredLogin {
            project: Url::parse(project).unwrap(),
            identity: HostedIdentity {
                user_id: uuid::Uuid::from_u128(1),
                session_id: uuid::Uuid::from_u128(2),
            },
            refresh_token: Zeroizing::new("synthetic-refresh".into()),
        };
        assert!(store.load().unwrap().is_none());
        store.save(&login).unwrap();
        let oversized = StoredLogin {
            project: login.project.clone(),
            identity: login.identity,
            refresh_token: Zeroizing::new("\"".repeat(4096)),
        };
        let oversized_result = store.save(&oversized);
        // Windows Credential Manager's native blob limit is lower than the record limit.
        #[cfg(target_os = "windows")]
        let native_limit_result = {
            store.save(&StoredLogin {
                refresh_token: Zeroizing::new("a".repeat(3000)),
                ..oversized
            })
        };
        let loaded = PlatformLoginStore::new(project, &profile).unwrap().load();
        let cleared = store.clear();
        cleared.unwrap();
        assert!(oversized_result.is_err());
        #[cfg(target_os = "windows")]
        assert!(native_limit_result.is_err());
        let loaded = loaded.unwrap().unwrap();
        assert!(loaded.identity == login.identity);
        assert_eq!(*loaded.refresh_token, *login.refresh_token);
        assert!(store.load().unwrap().is_none());
        store.clear().unwrap();
    }

    #[test]
    fn stored_record_is_bound_and_rejects_invalid_or_extra_fields() {
        let project = Url::parse("https://example.supabase.co/").unwrap();
        let login = StoredLogin {
            project: project.clone(),
            identity: HostedIdentity {
                user_id: uuid::Uuid::from_u128(1),
                session_id: uuid::Uuid::from_u128(2),
            },
            refresh_token: Zeroizing::new("synthetic-refresh".into()),
        };
        let bytes = login.encode().unwrap();
        let oversized = StoredLogin {
            project: login.project.clone(),
            identity: login.identity,
            refresh_token: Zeroizing::new("\"".repeat(4096)),
        };
        assert!(oversized.encode().is_err());
        assert!(StoredLogin::decode(&vec![b'x'; 8193], &project).is_err());
        let decoded = StoredLogin::decode(&bytes, &project).unwrap();
        assert!(decoded.identity == login.identity);
        assert_eq!(*decoded.refresh_token, *login.refresh_token);
        assert!(
            StoredLogin::decode(&bytes, &Url::parse("https://other.supabase.co/").unwrap())
                .is_err()
        );
        for (field, value) in [
            ("version", serde_json::json!(2)),
            (
                "user_id",
                serde_json::json!("00000000-0000-0000-0000-000000000000"),
            ),
            ("session_id", serde_json::json!("bad")),
            ("refresh_token", serde_json::json!("\n")),
            ("access_token", serde_json::json!("must-not-persist")),
        ] {
            let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            record[field] = value;
            assert!(StoredLogin::decode(&serde_json::to_vec(&record).unwrap(), &project).is_err());
        }
    }
}
