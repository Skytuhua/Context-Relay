use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use context_relay_protocol::{
    ClientRole, DaemonInstanceNonce, InstallationTokenProof, LocalRequest, PROTOCOL_VERSION,
    ProtocolVersion, RecordId,
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::IpcError;

pub const INSTALLATION_TOKEN_CREDENTIAL_SERVICE: &str = "Context Relay";
pub const INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT: &str = "installation-token-v1";
const AUTH_DOMAIN: &[u8] = b"context-relay.local-ipc.auth.v1\0";
const SERVER_AUTH_DOMAIN: &[u8] = b"context-relay.local-ipc.server-auth.v1\0";

type HmacSha256 = Hmac<Sha256>;

pub struct InstallationToken(Zeroizing<[u8; 32]>);

impl InstallationToken {
    pub fn generate() -> Result<Self, IpcError> {
        Ok(Self::from_bytes(random_bytes()?))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for InstallationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallationToken([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionChallenge([u8; 32]);

impl ConnectionChallenge {
    pub fn generate() -> Result<Self, IpcError> {
        Ok(Self(random_bytes()?))
    }

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for ConnectionChallenge {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for ConnectionChallenge {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = URL_SAFE_NO_PAD
            .decode(String::deserialize(deserializer)?)
            .map_err(D::Error::custom)?;
        Ok(Self(bytes.try_into().map_err(|_| {
            D::Error::custom("connection challenge must be 32 bytes")
        })?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerHelloV1 {
    pub protocol: ProtocolVersion,
    pub daemon_instance_nonce: DaemonInstanceNonce,
    pub connection_challenge: ConnectionChallenge,
}

impl ServerHelloV1 {
    pub fn generate(daemon_instance_nonce: DaemonInstanceNonce) -> Result<Self, IpcError> {
        Ok(Self {
            protocol: PROTOCOL_VERSION,
            daemon_instance_nonce,
            connection_challenge: ConnectionChallenge::generate()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthTranscriptV1 {
    pub role: ClientRole,
    pub client_nonce: DaemonInstanceNonce,
    pub server_hello: ServerHelloV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthAcceptedV1 {
    pub request_id: RecordId,
    pub server_proof: InstallationTokenProof,
}

pub fn create_proof(
    token: &InstallationToken,
    transcript: &AuthTranscriptV1,
) -> InstallationTokenProof {
    let mut mac = new_mac(token);
    update_transcript(
        &mut mac,
        AUTH_DOMAIN,
        transcript.role,
        &transcript.client_nonce,
        &transcript.server_hello.daemon_instance_nonce,
        &transcript.server_hello.connection_challenge,
        transcript.server_hello.protocol,
    );
    InstallationTokenProof(mac.finalize().into_bytes().into())
}

pub fn verify_proof(
    token: &InstallationToken,
    transcript: &AuthTranscriptV1,
    proof: &InstallationTokenProof,
) -> Result<(), IpcError> {
    let mut mac = new_mac(token);
    update_transcript(
        &mut mac,
        AUTH_DOMAIN,
        transcript.role,
        &transcript.client_nonce,
        &transcript.server_hello.daemon_instance_nonce,
        &transcript.server_hello.connection_challenge,
        transcript.server_hello.protocol,
    );
    mac.verify_slice(proof.as_bytes())
        .map_err(|_| IpcError::AuthenticationFailed)
}

pub fn create_server_proof(
    token: &InstallationToken,
    transcript: &AuthTranscriptV1,
    client_proof: &InstallationTokenProof,
) -> InstallationTokenProof {
    let mut mac = new_mac(token);
    update_transcript(
        &mut mac,
        SERVER_AUTH_DOMAIN,
        transcript.role,
        &transcript.client_nonce,
        &transcript.server_hello.daemon_instance_nonce,
        &transcript.server_hello.connection_challenge,
        transcript.server_hello.protocol,
    );
    mac.update(client_proof.as_bytes());
    InstallationTokenProof(mac.finalize().into_bytes().into())
}

pub fn verify_server_proof(
    token: &InstallationToken,
    transcript: &AuthTranscriptV1,
    client_proof: &InstallationTokenProof,
    server_proof: &InstallationTokenProof,
) -> Result<(), IpcError> {
    let mut mac = new_mac(token);
    update_transcript(
        &mut mac,
        SERVER_AUTH_DOMAIN,
        transcript.role,
        &transcript.client_nonce,
        &transcript.server_hello.daemon_instance_nonce,
        &transcript.server_hello.connection_challenge,
        transcript.server_hello.protocol,
    );
    mac.update(client_proof.as_bytes());
    mac.verify_slice(server_proof.as_bytes())
        .map_err(|_| IpcError::AuthenticationFailed)
}

pub fn role_allows(role: ClientRole, request: &LocalRequest) -> bool {
    use ClientRole::{Desktop, Installer, McpBridge};

    match request {
        LocalRequest::Hello(_) => false,
        LocalRequest::Cancel(_) => true,
        LocalRequest::Shutdown(_) => matches!(role, Desktop),
        LocalRequest::Health(_) => true,
        LocalRequest::Unlock(_) => matches!(role, Desktop),
        LocalRequest::ProjectsList(_) => matches!(role, Desktop),
        LocalRequest::ProjectPathSet(_) => matches!(role, Desktop),
        LocalRequest::MemoryGet(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::MemorySearch(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::MemoryCreate(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::MemoryUpdate(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::MemoryArchive(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::CandidatesList(_) => matches!(role, Desktop),
        LocalRequest::CandidateReview(_) => matches!(role, Desktop),
        LocalRequest::TasksList(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::TaskUpsert(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::TaskComplete(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::TaskTransition(_) => matches!(role, Desktop),
        LocalRequest::HandoffCreate(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::AccessGet(_) => matches!(role, Desktop | Installer),
        LocalRequest::AccessSet(_) => matches!(role, Desktop | Installer),
        LocalRequest::HarnessProbe(_) => matches!(role, Desktop | Installer),
        LocalRequest::HarnessPreview(_) => matches!(role, Desktop | Installer),
        LocalRequest::HarnessApply(_) => matches!(role, Desktop | Installer),
        LocalRequest::HarnessRepair(_) => matches!(role, Desktop | Installer),
        LocalRequest::HarnessRollback(_) => matches!(role, Desktop | Installer),
        LocalRequest::PackageImport(_) => matches!(role, Desktop | Installer),
        LocalRequest::PackageExport(_) => matches!(role, Desktop | Installer),
        LocalRequest::SyncStatus(_) => matches!(role, Desktop | McpBridge),
        LocalRequest::SyncRetry(_) => matches!(role, Desktop),
        LocalRequest::DevicesList(_) => matches!(role, Desktop),
        LocalRequest::DeviceRename(_) => matches!(role, Desktop),
        LocalRequest::DeviceRevoke(_) => matches!(role, Desktop),
        LocalRequest::PairingCreate(_) => matches!(role, Desktop),
        LocalRequest::PairingJoin(_) => matches!(role, Desktop),
        LocalRequest::PairingStatus(_) => matches!(role, Desktop),
        LocalRequest::PairingDecision(_) => matches!(role, Desktop),
        LocalRequest::PairingCancel(_) => matches!(role, Desktop),
        LocalRequest::RecoveryBegin(_) => matches!(role, Desktop),
        LocalRequest::RecoveryComplete(_) => matches!(role, Desktop),
        LocalRequest::ExportRecords(_) => matches!(role, Desktop),
        LocalRequest::ExportChunk(_) => matches!(role, Desktop),
        LocalRequest::AccountDeletionBegin(_) => matches!(role, Desktop),
        LocalRequest::AccountDeletionStatus(_) => matches!(role, Desktop),
        LocalRequest::AccountDeletionCancel(_) => matches!(role, Desktop),
    }
}

pub fn load_installation_token() -> Result<InstallationToken, IpcError> {
    let entry = credential_entry()?;
    load_token_from(|| read_credential(&entry))
}

pub fn generate_instance_nonce() -> Result<DaemonInstanceNonce, IpcError> {
    Ok(DaemonInstanceNonce::new(random_bytes()?))
}

fn random_bytes() -> Result<[u8; 32], IpcError> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| IpcError::Random)?;
    Ok(bytes)
}

fn new_mac(token: &InstallationToken) -> HmacSha256 {
    HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC accepts keys of any length")
}

fn update_transcript(
    mac: &mut HmacSha256,
    domain: &[u8],
    role: ClientRole,
    client_nonce: &DaemonInstanceNonce,
    daemon_nonce: &DaemonInstanceNonce,
    challenge: &ConnectionChallenge,
    version: ProtocolVersion,
) {
    mac.update(domain);
    mac.update(&[role_tag(role)]);
    mac.update(client_nonce.as_bytes());
    mac.update(daemon_nonce.as_bytes());
    mac.update(challenge.as_bytes());
    mac.update(&version.major.to_be_bytes());
    mac.update(&version.minor.to_be_bytes());
}

const fn role_tag(role: ClientRole) -> u8 {
    match role {
        ClientRole::Desktop => 0x01,
        ClientRole::McpBridge => 0x02,
        ClientRole::Installer => 0x03,
    }
}

fn credential_entry() -> Result<keyring::Entry, IpcError> {
    keyring::Entry::new(
        INSTALLATION_TOKEN_CREDENTIAL_SERVICE,
        INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT,
    )
    .map_err(|_| IpcError::Credential)
}

fn read_credential(entry: &keyring::Entry) -> Result<Option<Vec<u8>>, IpcError> {
    match entry.get_secret() {
        Ok(bytes) => Ok(Some(bytes)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(IpcError::Credential),
    }
}

fn load_token_from(
    load: impl FnOnce() -> Result<Option<Vec<u8>>, IpcError>,
) -> Result<InstallationToken, IpcError> {
    let decoded = Zeroizing::new(load()?.ok_or(IpcError::MissingToken)?);
    Ok(InstallationToken::from_bytes(
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| IpcError::InvalidToken)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpcError;

    #[test]
    fn client_load_does_not_create_a_missing_token() {
        let result = load_token_from(|| Ok(None));

        assert!(matches!(result, Err(IpcError::MissingToken)));
    }

    #[test]
    fn stored_token_must_be_exactly_32_bytes() {
        for length in [31, 33] {
            assert!(matches!(
                load_token_from(|| Ok(Some(vec![0x11; length]))),
                Err(IpcError::InvalidToken)
            ));
        }
    }
}
