//! Proposed v1 historical-key transport codec. These proofs authenticate key
//! inventory at independently accepted D, not durable activation, global freshness,
//! checkpoint reconstruction, target nonregression, or current write authority.
use super::{
    crypto::{
        PairingKeyBundle, certificate_digest, control_v2::ConfirmedV2Transcript,
        decode_pairing_key_bundle, decode_wrapped_envelope_with_limit, encode_pairing_key_bundle,
        encode_wrapped_envelope,
    },
    membership_crypto::{DeviceMembershipAddStatementV1, VerifiedMembershipLineage},
};
use crate::{
    crypto::{
        CryptoError, DeviceKeys, WrappedKeyEnvelope, validate_x25519_public_key, verify_signature,
        wrap_secret,
    },
    sync::SyncScope,
};
use context_relay_protocol::{
    AccountId, DeviceId, Ed25519SignatureBytes, OperationId, Sha256Digest, WorkspaceId,
    decode_checkpoint_v1, encode_checkpoint_signing_preimage_v1,
};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const HEADER_DOMAIN: &[u8] = b"context-relay/historical-key-transfer/v1\0";
const PAGE_DOMAIN: &[u8] = b"context-relay/historical-key-page/v1\0";
pub const MAX_PAGE_BYTES: usize = 16 * 1024;
pub const BUNDLES_PER_PAGE: u32 = 32;
const MAX_BUNDLE_BYTES: usize = 160;
const ZERO: Sha256Digest = Sha256Digest([0; 32]);
fn invalid<T>(_: T) -> CryptoError {
    CryptoError::InvalidProtocolValue
}
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}
fn page_count(last: u32) -> u32 {
    last.div_ceil(BUNDLES_PER_PAGE)
}
fn page_inventory(last: u32, index: u32) -> Result<(u32, u32), CryptoError> {
    if index >= page_count(last) {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let first = index
        .checked_mul(BUNDLES_PER_PAGE)
        .and_then(|v| v.checked_add(1))
        .ok_or(CryptoError::InvalidProtocolValue)?;
    Ok((first, (last - first + 1).min(BUNDLES_PER_PAGE)))
}

/// Untrusted decoded fields. Authority comes only from `HistoricalTransferAuthority`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferContext {
    pub transfer_id: OperationId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub pairing_membership_successor_sha256: Sha256Digest,
    pub authorizing_control_state_sha256: Sha256Digest,
    pub recipient_device_id: DeviceId,
    pub recipient_certificate_sha256: Sha256Digest,
    pub enrollment_record_sha256: Sha256Digest,
    pub exporter_device_id: DeviceId,
    pub checkpoint_sha256: Sha256Digest,
    pub last_historical_key_epoch: u32,
    pub page_count: u32,
}
impl TransferContext {
    fn bytes(&self) -> Result<Vec<u8>, CryptoError> {
        if self.last_historical_key_epoch == u32::MAX
            || self.page_count != page_count(self.last_historical_key_epoch)
            || [
                self.pairing_membership_successor_sha256,
                self.authorizing_control_state_sha256,
                self.recipient_certificate_sha256,
                self.enrollment_record_sha256,
                self.checkpoint_sha256,
            ]
            .contains(&ZERO)
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut out = Vec::with_capacity(250);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(self.transfer_id.as_bytes());
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.workspace_id.as_bytes());
        out.extend_from_slice(&self.pairing_membership_successor_sha256.0);
        out.extend_from_slice(&self.authorizing_control_state_sha256.0);
        out.extend_from_slice(self.recipient_device_id.as_bytes());
        out.extend_from_slice(&self.recipient_certificate_sha256.0);
        out.extend_from_slice(&self.enrollment_record_sha256.0);
        out.extend_from_slice(self.exporter_device_id.as_bytes());
        out.extend_from_slice(&self.checkpoint_sha256.0);
        out.extend_from_slice(&self.last_historical_key_epoch.to_be_bytes());
        out.extend_from_slice(&self.page_count.to_be_bytes());
        Ok(out)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalTransferHeader {
    pub context: TransferContext,
    pub first_page_sha256: Sha256Digest,
    pub signature: Ed25519SignatureBytes,
}
impl HistoricalTransferHeader {
    fn preimage(&self) -> Result<Vec<u8>, CryptoError> {
        if (self.context.page_count == 0) != (self.first_page_sha256 == ZERO) {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut out = HEADER_DOMAIN.to_vec();
        out.extend(self.context.bytes()?);
        out.extend(self.first_page_sha256.0);
        Ok(out)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = self.preimage()?;
        out.extend(self.signature.0);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HEADER_DOMAIN.len() + 346 {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut input = bytes
            .strip_prefix(HEADER_DOMAIN)
            .ok_or(CryptoError::InvalidProtocolValue)?;
        fn take<const N: usize>(input: &mut &[u8]) -> [u8; N] {
            let (a, b) = input.split_at(N);
            *input = b;
            a.try_into().expect("fixed header length checked")
        }
        if u16::from_be_bytes(take(&mut input)) != 1 {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let context = TransferContext {
            transfer_id: OperationId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(invalid)?,
            account_id: AccountId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(invalid)?,
            workspace_id: WorkspaceId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(invalid)?,
            pairing_membership_successor_sha256: Sha256Digest(take(&mut input)),
            authorizing_control_state_sha256: Sha256Digest(take(&mut input)),
            recipient_device_id: DeviceId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(invalid)?,
            recipient_certificate_sha256: Sha256Digest(take(&mut input)),
            enrollment_record_sha256: Sha256Digest(take(&mut input)),
            exporter_device_id: DeviceId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(invalid)?,
            checkpoint_sha256: Sha256Digest(take(&mut input)),
            last_historical_key_epoch: u32::from_be_bytes(take(&mut input)),
            page_count: u32::from_be_bytes(take(&mut input)),
        };
        let h = Self {
            context,
            first_page_sha256: Sha256Digest(take(&mut input)),
            signature: Ed25519SignatureBytes(take(&mut input)),
        };
        if h.canonical_bytes()? != bytes {
            return Err(CryptoError::InvalidProtocolValue);
        }
        Ok(h)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransferPage {
    index: u32,
    first_key_epoch: u32,
    bundle_count: u32,
    next_page_sha256: Sha256Digest,
    envelope: WrappedKeyEnvelope,
}
impl TransferPage {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        if self.first_key_epoch == 0
            || !(1..=BUNDLES_PER_PAGE).contains(&self.bundle_count)
            || !(16..=MAX_PAGE_BYTES).contains(&self.envelope.ciphertext.len())
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        validate_x25519_public_key(self.envelope.ephemeral_public_key)?;
        let mut e = Encoder::new(Vec::new());
        e.map(5)
            .map_err(invalid)?
            .u8(0)
            .map_err(invalid)?
            .u32(self.index)
            .map_err(invalid)?
            .u8(1)
            .map_err(invalid)?
            .u32(self.first_key_epoch)
            .map_err(invalid)?
            .u8(2)
            .map_err(invalid)?
            .u32(self.bundle_count)
            .map_err(invalid)?
            .u8(3)
            .map_err(invalid)?
            .bytes(&self.next_page_sha256.0)
            .map_err(invalid)?
            .u8(4)
            .map_err(invalid)?;
        encode_wrapped_envelope(&mut e, &self.envelope)?;
        let out = e.into_writer();
        if out.len() > MAX_PAGE_BYTES {
            return Err(CryptoError::InvalidProtocolValue);
        }
        Ok(out)
    }
    fn decode(raw: &[u8]) -> Result<Self, CryptoError> {
        if raw.len() > MAX_PAGE_BYTES {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut d = Decoder::new(raw);
        if d.map().map_err(invalid)? != Some(5) {
            return Err(CryptoError::InvalidProtocolValue);
        }
        fn key(d: &mut Decoder<'_>, k: u8) -> Result<(), CryptoError> {
            if d.u8().map_err(invalid)? != k {
                return Err(CryptoError::InvalidProtocolValue);
            }
            Ok(())
        }
        key(&mut d, 0)?;
        let index = d.u32().map_err(invalid)?;
        key(&mut d, 1)?;
        let first_key_epoch = d.u32().map_err(invalid)?;
        key(&mut d, 2)?;
        let bundle_count = d.u32().map_err(invalid)?;
        key(&mut d, 3)?;
        let next_page_sha256 =
            Sha256Digest(d.bytes().map_err(invalid)?.try_into().map_err(invalid)?);
        key(&mut d, 4)?;
        let envelope = decode_wrapped_envelope_with_limit(&mut d, MAX_PAGE_BYTES)?;
        let p = Self {
            index,
            first_key_epoch,
            bundle_count,
            next_page_sha256,
            envelope,
        };
        if d.position() != raw.len() || p.canonical_bytes()? != raw {
            return Err(CryptoError::InvalidProtocolValue);
        }
        Ok(p)
    }
    fn aad(&self, c: &TransferContext) -> Result<Vec<u8>, CryptoError> {
        let mut out = PAGE_DOMAIN.to_vec();
        out.extend(c.bytes()?);
        out.extend(self.index.to_be_bytes());
        out.extend(self.first_key_epoch.to_be_bytes());
        out.extend(self.bundle_count.to_be_bytes());
        out.extend(self.next_page_sha256.0);
        Ok(out)
    }
}

/// Explicit epoch-one trust choice: genesis has no public plaintext commitment.
/// A previous trusted value must be supplied when one exists locally.
#[derive(Clone, Copy)]
pub enum EpochOneTrust<'a> {
    ActiveExporterAssertion,
    PreviouslyTrusted(&'a PairingKeyBundle),
}

/// Created only from independently trusted lineage and the exact confirmed C
/// admission transcript. Checkpoint authentication here is a read-target assertion;
/// callers still owe frontier nonregression, reconstruction and transaction CAS.
pub struct HistoricalTransferAuthority<'a> {
    context: TransferContext,
    lineage: &'a VerifiedMembershipLineage,
}
impl<'a> HistoricalTransferAuthority<'a> {
    pub fn new(
        lineage: &'a VerifiedMembershipLineage,
        confirmed: &ConfirmedV2Transcript,
        membership_signature: Ed25519SignatureBytes,
        transfer_id: OperationId,
        exporter: DeviceId,
        checkpoint_bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        let fail = CryptoError::AuthenticationFailed;
        let s = lineage.history().state();
        let p = confirmed.payload();
        let cert = &p.grant.certificate;
        let statement =
            DeviceMembershipAddStatementV1::from_approved_payload_v2(confirmed.canonical_bytes())?;
        let anchor = lineage.anchor();
        if statement.control_state_sha256(membership_signature)? != anchor.state_sha256
            || statement.control_epoch != anchor.control_epoch
            || statement.key_epoch != anchor.key_epoch
            || cert.account_id != s.scope.account_id
            || cert.workspace_id != s.scope.workspace_id
            || s.active_devices.get(&cert.device_id) != Some(cert)
            || lineage.history().admissions().get(&cert.device_id) != Some(&p.grant.certificate_id)
            || lineage
                .history()
                .pairing_parent(exporter)?
                .enrollment_record_sha256
                != confirmed.enrollment_record_sha256()
        {
            return Err(fail);
        }
        verify_signature(
            p.issuer_certificate.signing_public_key,
            &statement.signing_preimage()?,
            membership_signature,
        )?;
        let exporter_cert = s.active_devices.get(&exporter).ok_or(fail)?;
        let checkpoint = decode_checkpoint_v1(checkpoint_bytes).map_err(invalid)?;
        if checkpoint.account_id != s.scope.account_id
            || checkpoint.workspace_id != s.scope.workspace_id
            || checkpoint.key_epoch != s.key_epoch
            || checkpoint.creator_device != exporter
            || checkpoint.created_hlc.node != exporter
        {
            return Err(fail);
        }
        verify_signature(
            exporter_cert.signing_public_key,
            &encode_checkpoint_signing_preimage_v1(&checkpoint).map_err(invalid)?,
            checkpoint.signature,
        )?;
        let last = s.key_epoch.checked_sub(1).ok_or(fail)?;
        let context = TransferContext {
            transfer_id,
            account_id: s.scope.account_id,
            workspace_id: s.scope.workspace_id,
            pairing_membership_successor_sha256: anchor.state_sha256,
            authorizing_control_state_sha256: s.state_sha256,
            recipient_device_id: cert.device_id,
            recipient_certificate_sha256: certificate_digest(cert)?,
            enrollment_record_sha256: confirmed.enrollment_record_sha256(),
            exporter_device_id: exporter,
            checkpoint_sha256: digest(checkpoint_bytes),
            last_historical_key_epoch: last,
            page_count: page_count(last),
        };
        context.bytes()?;
        Ok(Self { context, lineage })
    }
    pub fn context(&self) -> &TransferContext {
        &self.context
    }
    fn check_keys(&self, id: DeviceId, keys: &DeviceKeys) -> Result<(), CryptoError> {
        let s = self.lineage.history().state();
        let cert = s
            .active_devices
            .get(&id)
            .ok_or(CryptoError::AuthenticationFailed)?;
        if cert.signing_public_key != keys.signing_public_key()
            || cert.wrapping_public_key != keys.wrapping_public_key()
        {
            return Err(CryptoError::InvalidKey);
        }
        Ok(())
    }
    fn check_bundle(
        &self,
        b: &PairingKeyBundle,
        epoch: u32,
        genesis: EpochOneTrust<'_>,
    ) -> Result<(), CryptoError> {
        let c = &self.context;
        if b.account_id() != c.account_id
            || b.workspace_id() != c.workspace_id
            || b.key_epoch() != epoch
            || b.enrollment_record_sha256() != Some(c.enrollment_record_sha256)
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        if epoch == 1 {
            if b.control_epoch() != 1 {
                return Err(CryptoError::AuthenticationFailed);
            }
            if let EpochOneTrust::PreviouslyTrusted(trusted) = genesis
                && encode_pairing_key_bundle(b)?.as_slice()
                    != encode_pairing_key_bundle(trusted)?.as_slice()
            {
                return Err(CryptoError::AuthenticationFailed);
            }
        } else {
            let commitment = self
                .lineage
                .rotated_key_commitments()
                .get((epoch - 2) as usize)
                .ok_or(CryptoError::AuthenticationFailed)?;
            if commitment.key_epoch() != epoch || commitment.control_epoch() != b.control_epoch() {
                return Err(CryptoError::AuthenticationFailed);
            }
            let unpinned = PairingKeyBundle::new(
                SyncScope {
                    account_id: b.account_id(),
                    workspace_id: b.workspace_id(),
                },
                b.control_epoch(),
                b.key_epoch(),
                *b.workspace_root_key(),
                *b.active_epoch_key(),
            )?;
            if digest(&encode_pairing_key_bundle(b)?) != commitment.key_material_sha256()
                && digest(&encode_pairing_key_bundle(&unpinned)?)
                    != commitment.key_material_sha256()
            {
                return Err(CryptoError::AuthenticationFailed);
            }
        }
        Ok(())
    }
    /// Build backward, one bounded page at a time. Persist exact bytes before
    /// signing the header. Retry storage and transfer-ID immutability are external.
    pub fn build_page(
        &self,
        index: u32,
        next: Sha256Digest,
        bundles: &[PairingKeyBundle],
        genesis: EpochOneTrust<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        let (first, count) = page_inventory(self.context.last_historical_key_epoch, index)?;
        if bundles.len() != count as usize
            || (index + 1 == self.context.page_count) != (next == ZERO)
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        // Complete capacity prevents reallocations leaving copied plaintext behind.
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            2 + BUNDLES_PER_PAGE as usize * (MAX_BUNDLE_BYTES + 2),
        ));
        let mut e = Encoder::new(&mut *plaintext);
        e.array(u64::from(count)).map_err(invalid)?;
        for (offset, b) in bundles.iter().enumerate() {
            self.check_bundle(b, first + offset as u32, genesis)?;
            e.bytes(&encode_pairing_key_bundle(b)?).map_err(invalid)?;
        }
        let mut page = TransferPage {
            index,
            first_key_epoch: first,
            bundle_count: count,
            next_page_sha256: next,
            envelope: WrappedKeyEnvelope {
                ephemeral_public_key: self.lineage.history().state().active_devices
                    [&self.context.recipient_device_id]
                    .wrapping_public_key,
                nonce: context_relay_protocol::XChaChaNonce([0; 24]),
                ciphertext: Vec::new(),
            },
        };
        page.envelope = wrap_secret(
            page.envelope.ephemeral_public_key,
            &plaintext,
            &page.aad(&self.context)?,
        )?;
        page.canonical_bytes()
    }
    pub fn sign_header(
        &self,
        first_page_sha256: Sha256Digest,
        keys: &DeviceKeys,
    ) -> Result<HistoricalTransferHeader, CryptoError> {
        self.check_keys(self.context.exporter_device_id, keys)?;
        let mut h = HistoricalTransferHeader {
            context: self.context.clone(),
            first_page_sha256,
            signature: Ed25519SignatureBytes([0; 64]),
        };
        h.signature = keys.sign_hosted_device_proof(&h.preimage()?);
        Ok(h)
    }
    pub fn verify_header(
        &self,
        raw: &[u8],
    ) -> Result<VerifiedHistoricalTransfer<'_, 'a>, CryptoError> {
        let h = HistoricalTransferHeader::decode(raw)?;
        if h.context != self.context {
            return Err(CryptoError::AuthenticationFailed);
        }
        verify_signature(
            self.lineage.history().state().active_devices[&self.context.exporter_device_id]
                .signing_public_key,
            &h.preimage()?,
            h.signature,
        )?;
        Ok(VerifiedHistoricalTransfer {
            authority: self,
            next_index: 0,
            next_hash: h.first_page_sha256,
        })
    }
}

/// In-memory, sequential key inventory verification only. No public constructor,
/// restored cursor, installation, current-material proof, or completed-history flag.
pub struct VerifiedHistoricalTransfer<'a, 'b> {
    authority: &'a HistoricalTransferAuthority<'b>,
    next_index: u32,
    next_hash: Sha256Digest,
}
impl VerifiedHistoricalTransfer<'_, '_> {
    pub fn next_page(&self) -> Option<(u32, Sha256Digest)> {
        (!self.inventory_verified()).then_some((self.next_index, self.next_hash))
    }
    pub fn inventory_verified(&self) -> bool {
        self.next_index == self.authority.context.page_count && self.next_hash == ZERO
    }
    pub fn open_next_page(
        &mut self,
        raw: &[u8],
        keys: &DeviceKeys,
        genesis: EpochOneTrust<'_>,
    ) -> Result<Vec<PairingKeyBundle>, CryptoError> {
        let a = self.authority;
        a.check_keys(a.context.recipient_device_id, keys)?;
        if raw.len() > MAX_PAGE_BYTES || self.inventory_verified() || digest(raw) != self.next_hash
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        let p = TransferPage::decode(raw)?;
        let (first, count) = page_inventory(a.context.last_historical_key_epoch, self.next_index)?;
        if p.index != self.next_index
            || p.first_key_epoch != first
            || p.bundle_count != count
            || (p.index + 1 == a.context.page_count) != (p.next_page_sha256 == ZERO)
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        let plaintext = keys.unwrap_secret(&p.envelope, &p.aad(&a.context)?)?;
        let mut d = Decoder::new(plaintext.expose());
        if d.array().map_err(invalid)? != Some(u64::from(count)) {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut bundles = Vec::with_capacity(count as usize);
        let mut canonical_bytes = Zeroizing::new(Vec::with_capacity(
            2 + BUNDLES_PER_PAGE as usize * (MAX_BUNDLE_BYTES + 2),
        ));
        let mut canonical = Encoder::new(&mut *canonical_bytes);
        canonical.array(u64::from(count)).map_err(invalid)?;
        for epoch in first..first + count {
            let raw = d.bytes().map_err(invalid)?;
            if raw.len() > MAX_BUNDLE_BYTES {
                return Err(CryptoError::InvalidProtocolValue);
            }
            let b = decode_pairing_key_bundle(raw)?;
            a.check_bundle(&b, epoch, genesis)?;
            canonical.bytes(raw).map_err(invalid)?;
            bundles.push(b);
        }
        if d.position() != plaintext.expose().len()
            || canonical_bytes.as_slice() != plaintext.expose()
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        self.next_index += 1;
        self.next_hash = p.next_page_sha256;
        Ok(bundles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{CertificateFieldsV1, DeviceCertificateV1, RecoveryKeys, RecoveryPhrase},
        devices::{
            crypto::{SignedPairingRequest, control_v2::*},
            membership_crypto::*,
            recovery_crypto::{
                RecoveryEnrollmentBuildRequest, build_recovery_enrollment_artifacts,
            },
            revocation_crypto::{
                DeviceRevocationStatementV1, RevocationTransitionV1,
                initial_revocation_control_state,
            },
        },
    };
    use context_relay_protocol::{
        CHECKPOINT_SCHEMA_VERSION, CheckpointV1, HybridLogicalClock, NativePlatform,
        PairingRequestNonce, encode_checkpoint_v1,
    };
    use std::collections::BTreeMap;

    struct Fixture {
        lineage: VerifiedMembershipLineage,
        confirmed: ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        keys: DeviceKeys,
        exporter_keys: DeviceKeys,
        bundles: Vec<PairingKeyBundle>,
        checkpoint: Vec<u8>,
        enrollment: Vec<u8>,
        events: Vec<Event>,
        genesis: MembershipEndpoint,
    }
    enum Event {
        Add(
            Vec<u8>,
            Ed25519SignatureBytes,
            Box<SignedPairingRequest>,
            Vec<u8>,
        ),
        Rotate(Vec<u8>, Ed25519SignatureBytes, Vec<u8>),
    }
    impl Event {
        fn borrowed(&self) -> MembershipHistoryEvent<'_> {
            match self {
                Self::Add(statement, signature, request, approved_payload) => {
                    MembershipHistoryEvent::PairingAdd {
                        statement,
                        signature: *signature,
                        request,
                        approved_payload,
                    }
                }
                Self::Rotate(statement, signature, transition) => {
                    MembershipHistoryEvent::Revocation {
                        statement,
                        signature: *signature,
                        transition,
                    }
                }
            }
        }
    }
    fn fixture(rotations: u8) -> Fixture {
        let a = DeviceKeys::from_seeds([1; 32], [2; 32]);
        let b = DeviceKeys::from_seeds([3; 32], [4; 32]);
        let recovery =
            RecoveryKeys::derive(&RecoveryPhrase::from_entropy([7; 32]).unwrap()).unwrap();
        let scope = SyncScope {
            account_id: id(1),
            workspace_id: id(2),
        };
        let cert = DeviceCertificateV1::issue_genesis(
            CertificateFieldsV1 {
                account_id: id(1),
                workspace_id: id(2),
                control_epoch: 1,
                request_nonce: PairingRequestNonce([3; 32]),
                device_id: id(3),
                signing_public_key: a.signing_public_key(),
                wrapping_public_key: a.wrapping_public_key(),
            },
            &recovery,
        )
        .unwrap();
        let initial = PairingKeyBundle::new(scope, 1, 1, [21; 32], [22; 32]).unwrap();
        let enrollment = build_recovery_enrollment_artifacts(RecoveryEnrollmentBuildRequest {
            enrollment_id: id(6),
            recovery_root_id: id(7),
            certificate_id: id(8),
            certificate: cert.clone(),
            device_name: "A".into(),
            device_platform: NativePlatform::Windows,
            recovery_keys: &recovery,
            device_keys: &a,
            material: &initial,
        })
        .unwrap();
        let pin = enrollment.canonical_record_sha256;
        let initial = initial.with_enrollment_record_sha256(pin).unwrap();
        let roster = BTreeMap::from([(id(3), cert.clone())]);
        let g = initial_revocation_control_state(&enrollment.record, pin, scope, &roster).unwrap();
        let budget = MembershipHistoryBudget {
            max_events: 200,
            max_bytes: 2_000_000,
        };
        let mut endpoint = MembershipEndpoint {
            state_sha256: g.state_sha256,
            control_epoch: 1,
            key_epoch: 1,
        };
        let genesis = endpoint;
        let mut events: Vec<Event> = Vec::new();
        let replay = |events: &[Event], endpoint| {
            verify_membership_history(
                &enrollment.canonical_record,
                pin,
                scope,
                &events.iter().map(Event::borrowed).collect::<Vec<_>>(),
                endpoint,
                budget,
            )
            .unwrap()
        };
        let history = replay(&events, endpoint);
        let request =
            SignedPairingRequest::build(id(10), id(4), "B", NativePlatform::Windows, &b).unwrap();
        let built = build_pairing_approval_v2(
            &request,
            &history.pairing_parent(id(3)).unwrap(),
            id(3),
            &a,
            id(11),
            "A",
            NativePlatform::Windows,
            &initial,
        )
        .unwrap();
        let payload = encode_pairing_approved_payload_v2(&built.payload).unwrap();
        let confirmed =
            confirm_pairing_transcript_v2(&payload, built.safety_number.as_str(), &request)
                .unwrap();
        let statement = DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
        let signature = statement.sign(&cert, &a).unwrap();
        endpoint.state_sha256 = statement.control_state_sha256(signature).unwrap();
        let anchor = endpoint;
        events.push(Event::Add(
            statement.signing_preimage().unwrap(),
            signature,
            Box::new(request),
            payload,
        ));
        let mut bundles = vec![initial];
        for i in 0..rotations {
            let history = replay(&events, endpoint);
            let target = if i == 0 {
                id(3)
            } else {
                let n = 20 + 4 * i;
                let request = SignedPairingRequest::build(
                    id(n),
                    id(n + 1),
                    "victim",
                    NativePlatform::Windows,
                    &a,
                )
                .unwrap();
                let built = build_pairing_approval_v2(
                    &request,
                    &history.pairing_parent(id(4)).unwrap(),
                    id(4),
                    &b,
                    id(n + 2),
                    "B",
                    NativePlatform::Windows,
                    bundles.last().unwrap(),
                )
                .unwrap();
                let payload = encode_pairing_approved_payload_v2(&built.payload).unwrap();
                let statement =
                    DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
                let sig = statement
                    .sign(&confirmed.payload().grant.certificate, &b)
                    .unwrap();
                endpoint.state_sha256 = statement.control_state_sha256(sig).unwrap();
                events.push(Event::Add(
                    statement.signing_preimage().unwrap(),
                    sig,
                    Box::new(request),
                    payload,
                ));
                id(n + 1)
            };
            let history = replay(&events, endpoint);
            let statement = DeviceRevocationStatementV1 {
                schema_version: 1,
                revocation_id: id(20 + 4 * i + 3),
                account_id: id(1),
                workspace_id: id(2),
                issuer_device_id: id(4),
                target_device_id: target,
                control_epoch: endpoint.control_epoch,
                key_epoch: endpoint.key_epoch,
                cutoff_sequence: 0,
                cutoff_hash: ZERO,
                transition_sha256: Sha256Digest([1; 32]),
            };
            let (statement, transition, sig) =
                RevocationTransitionV1::build(statement, &b, &history.state()).unwrap();
            bundles.push(
                transition
                    .open_device_material(&statement, sig, &history.state(), id(4), &b)
                    .unwrap()
                    .with_enrollment_record_sha256(pin)
                    .unwrap(),
            );
            endpoint = MembershipEndpoint {
                state_sha256: statement.control_state_sha256(sig).unwrap(),
                control_epoch: endpoint.control_epoch + 1,
                key_epoch: endpoint.key_epoch + 1,
            };
            events.push(Event::Rotate(
                statement.signing_preimage().unwrap(),
                sig,
                transition.canonical_bytes().unwrap(),
            ));
        }
        // E joins after C and all rotations; its certificate is resolved at D.
        let exporter_keys = DeviceKeys::from_seeds([5; 32], [6; 32]);
        let history = replay(&events, endpoint);
        let request = SignedPairingRequest::build(
            id(180),
            id(181),
            "E",
            NativePlatform::Windows,
            &exporter_keys,
        )
        .unwrap();
        let built = build_pairing_approval_v2(
            &request,
            &history.pairing_parent(id(4)).unwrap(),
            id(4),
            &b,
            id(182),
            "B",
            NativePlatform::Windows,
            bundles.last().unwrap(),
        )
        .unwrap();
        let payload = encode_pairing_approved_payload_v2(&built.payload).unwrap();
        let statement = DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
        let sig = statement
            .sign(&confirmed.payload().grant.certificate, &b)
            .unwrap();
        endpoint.state_sha256 = statement.control_state_sha256(sig).unwrap();
        events.push(Event::Add(
            statement.signing_preimage().unwrap(),
            sig,
            Box::new(request),
            payload,
        ));
        let lineage = verify_membership_lineage(
            &enrollment.canonical_record,
            pin,
            scope,
            &events.iter().map(Event::borrowed).collect::<Vec<_>>(),
            anchor,
            endpoint,
            budget,
        )
        .unwrap();
        let mut checkpoint = CheckpointV1 {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            account_id: id(1),
            workspace_id: id(2),
            previous_checkpoint_hash: ZERO,
            causal_frontier: vec![],
            state_hash: Sha256Digest([9; 32]),
            key_epoch: endpoint.key_epoch,
            creator_device: id(181),
            created_hlc: HybridLogicalClock {
                physical_ms: 1,
                logical: 0,
                node: id(181),
            },
            signature: Ed25519SignatureBytes([0; 64]),
        };
        exporter_keys.sign_checkpoint(&mut checkpoint).unwrap();
        Fixture {
            lineage,
            confirmed,
            signature,
            keys: b,
            exporter_keys,
            bundles,
            checkpoint: encode_checkpoint_v1(&checkpoint).unwrap(),
            enrollment: enrollment.canonical_record,
            events,
            genesis,
        }
    }
    impl Fixture {
        fn authority(&self) -> HistoricalTransferAuthority<'_> {
            HistoricalTransferAuthority::new(
                &self.lineage,
                &self.confirmed,
                self.signature,
                id(200),
                id(181),
                &self.checkpoint,
            )
            .unwrap()
        }
    }

    #[test]
    fn historical_exact_admission_empty_and_private_acceptance() {
        let f = fixture(0);
        let a = f.authority();
        let h = a
            .sign_header(ZERO, &f.exporter_keys)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        let mut verified = a.verify_header(&h).unwrap();
        assert!(verified.inventory_verified());
        assert_eq!(verified.next_page(), None);
        assert!(
            verified
                .open_next_page(&[], &f.keys, EpochOneTrust::ActiveExporterAssertion)
                .is_err()
        );
        assert!(
            a.sign_header(Sha256Digest([1; 32]), &f.exporter_keys)
                .is_err()
        );
        assert!(
            a.sign_header(ZERO, &DeviceKeys::from_seeds([9; 32], [10; 32]))
                .is_err()
        );
        assert!(
            HistoricalTransferAuthority::new(
                &f.lineage,
                &f.confirmed,
                Ed25519SignatureBytes([0; 64]),
                id(200),
                id(181),
                &f.checkpoint
            )
            .is_err()
        );
        let mut checkpoint = f.checkpoint.clone();
        *checkpoint.last_mut().unwrap() ^= 1;
        assert!(
            HistoricalTransferAuthority::new(
                &f.lineage,
                &f.confirmed,
                f.signature,
                id(200),
                id(181),
                &checkpoint
            )
            .is_err()
        );
        for i in 0..h.len() {
            let mut altered = h.clone();
            altered[i] ^= 1;
            assert!(a.verify_header(&altered).is_err(), "byte {i}");
        }
    }

    #[test]
    fn historical_authority_rejects_other_anchors_and_revoked_recipient() {
        let mut f = fixture(1);
        let scope = SyncScope {
            account_id: id(1),
            workspace_id: id(2),
        };
        let pin = f.confirmed.enrollment_record_sha256();
        let endpoint = f.lineage.history().endpoint();
        let budget = MembershipHistoryBudget {
            max_events: 200,
            max_bytes: 2_000_000,
        };
        // Both are valid lineage anchors, but neither is B's exact admission C.
        for anchor in [f.genesis, endpoint] {
            let lineage = verify_membership_lineage(
                &f.enrollment,
                pin,
                scope,
                &f.events.iter().map(Event::borrowed).collect::<Vec<_>>(),
                anchor,
                endpoint,
                budget,
            )
            .unwrap();
            assert!(
                HistoricalTransferAuthority::new(
                    &lineage,
                    &f.confirmed,
                    f.signature,
                    id(200),
                    id(181),
                    &f.checkpoint
                )
                .is_err()
            );
        }
        let a = f.authority();
        assert!(a.sign_header(Sha256Digest([1; 32]), &f.keys).is_err());
        // A was revoked before D, and B did not sign E's checkpoint.
        for exporter in [id(3), id(4)] {
            assert!(
                HistoricalTransferAuthority::new(
                    &f.lineage,
                    &f.confirmed,
                    f.signature,
                    id(200),
                    exporter,
                    &f.checkpoint
                )
                .is_err()
            );
        }
        let statement = DeviceRevocationStatementV1 {
            schema_version: 1,
            revocation_id: id(190),
            account_id: id(1),
            workspace_id: id(2),
            issuer_device_id: id(181),
            target_device_id: id(4),
            control_epoch: endpoint.control_epoch,
            key_epoch: endpoint.key_epoch,
            cutoff_sequence: 0,
            cutoff_hash: ZERO,
            transition_sha256: Sha256Digest([1; 32]),
        };
        let (statement, transition, sig) = RevocationTransitionV1::build(
            statement,
            &f.exporter_keys,
            &f.lineage.history().state(),
        )
        .unwrap();
        let endpoint = MembershipEndpoint {
            state_sha256: statement.control_state_sha256(sig).unwrap(),
            control_epoch: endpoint.control_epoch + 1,
            key_epoch: endpoint.key_epoch + 1,
        };
        f.events.push(Event::Rotate(
            statement.signing_preimage().unwrap(),
            sig,
            transition.canonical_bytes().unwrap(),
        ));
        let lineage = verify_membership_lineage(
            &f.enrollment,
            pin,
            scope,
            &f.events.iter().map(Event::borrowed).collect::<Vec<_>>(),
            f.lineage.anchor(),
            endpoint,
            budget,
        )
        .unwrap();
        let mut checkpoint = decode_checkpoint_v1(&f.checkpoint).unwrap();
        checkpoint.key_epoch = endpoint.key_epoch;
        f.exporter_keys.sign_checkpoint(&mut checkpoint).unwrap();
        assert!(
            HistoricalTransferAuthority::new(
                &lineage,
                &f.confirmed,
                f.signature,
                id(200),
                id(181),
                &encode_checkpoint_v1(&checkpoint).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn historical_multipage_exact_inventory_commitments_and_hostile_delivery() {
        let f = fixture(33);
        let a = f.authority();
        let trust = EpochOneTrust::PreviouslyTrusted(&f.bundles[0]);
        let last = a.build_page(1, ZERO, &f.bundles[32..33], trust).unwrap();
        let first = a
            .build_page(0, digest(&last), &f.bundles[..32], trust)
            .unwrap();
        let header = a
            .sign_header(digest(&first), &f.exporter_keys)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        let mut v = a.verify_header(&header).unwrap();
        assert!(!v.inventory_verified());
        assert!(v.open_next_page(&last, &f.keys, trust).is_err());
        let saved = v.next_page();
        assert!(
            v.open_next_page(&first, &DeviceKeys::from_seeds([9; 32], [10; 32]), trust)
                .is_err()
        );
        assert_eq!(v.next_page(), saved);
        let wrong = PairingKeyBundle::new(
            SyncScope {
                account_id: id(1),
                workspace_id: id(2),
            },
            1,
            1,
            [0; 32],
            [0; 32],
        )
        .unwrap()
        .with_enrollment_record_sha256(a.context.enrollment_record_sha256)
        .unwrap();
        assert!(
            v.open_next_page(&first, &f.keys, EpochOneTrust::PreviouslyTrusted(&wrong))
                .is_err()
        );
        assert_eq!(v.next_page(), saved);
        let opened = v.open_next_page(&first, &f.keys, trust).unwrap();
        assert_eq!(opened.len(), 32);
        assert!(!v.inventory_verified());
        assert!(v.open_next_page(&first, &f.keys, trust).is_err());
        let opened = v.open_next_page(&last, &f.keys, trust).unwrap();
        assert_eq!(opened[0].key_epoch(), 33);
        assert!(v.inventory_verified());
        assert!(v.open_next_page(&last, &f.keys, trust).is_err());
        assert!(
            a.build_page(1, Sha256Digest([1; 32]), &f.bundles[32..33], trust)
                .is_err()
        );
        assert!(a.build_page(0, ZERO, &f.bundles[..32], trust).is_err());
        assert!(a.build_page(1, ZERO, &f.bundles[33..], trust).is_err()); // current epoch is not historical
        for (epoch, control, pin, root) in [
            (33, 33, a.context.enrollment_record_sha256, [0; 32]),
            (
                33,
                32,
                a.context.enrollment_record_sha256,
                *f.bundles[32].workspace_root_key(),
            ),
            (
                33,
                33,
                Sha256Digest([1; 32]),
                *f.bundles[32].workspace_root_key(),
            ),
        ] {
            let bad = PairingKeyBundle::new(
                SyncScope {
                    account_id: id(1),
                    workspace_id: id(2),
                },
                control,
                epoch,
                root,
                *f.bundles[32].active_epoch_key(),
            )
            .unwrap()
            .with_enrollment_record_sha256(pin)
            .unwrap();
            assert!(a.build_page(1, ZERO, &[bad], trust).is_err());
        }
        // Re-encrypt adversarial inner data, then validly sign its ciphertext hash.
        let mut page = TransferPage::decode(&last).unwrap();
        let original = f
            .keys
            .unwrap_secret(&page.envelope, &page.aad(&a.context).unwrap())
            .unwrap();
        let mut cases = vec![vec![0x80], vec![0x9f, 0xff]];
        let mut bad = original.expose().to_vec();
        bad.splice(0..1, [0x98, 1]);
        cases.push(bad);
        let mut bad = original.expose().to_vec();
        bad.push(0);
        cases.push(bad);
        let mut bad = original.expose().to_vec();
        bad[4] = 7;
        cases.push(bad);
        for bad in cases {
            page.envelope = wrap_secret(
                f.keys.wrapping_public_key(),
                &bad,
                &page.aad(&a.context).unwrap(),
            )
            .unwrap();
            let raw = page.canonical_bytes().unwrap();
            let first = a
                .build_page(0, digest(&raw), &f.bundles[..32], trust)
                .unwrap();
            let header = a
                .sign_header(digest(&first), &f.exporter_keys)
                .unwrap()
                .canonical_bytes()
                .unwrap();
            let mut v = a.verify_header(&header).unwrap();
            v.open_next_page(&first, &f.keys, trust).unwrap();
            let saved = v.next_page();
            assert!(v.open_next_page(&raw, &f.keys, trust).is_err());
            assert_eq!(v.next_page(), saved);
        }
    }

    #[test]
    fn historical_authenticated_hostile_plaintext_and_context_substitution() {
        let f = fixture(2);
        let a = f.authority();
        let trust = EpochOneTrust::PreviouslyTrusted(&f.bundles[0]);
        let raw = a.build_page(0, ZERO, &f.bundles[..2], trust).unwrap();
        let mut page = TransferPage::decode(&raw).unwrap();
        let scope = SyncScope {
            account_id: id(1),
            workspace_id: id(2),
        };
        let b = &f.bundles[1];
        let mut cases = Vec::new();
        // Each malformed bundle is wrapped in a canonical, correctly sized outer array.
        let unpinned =
            PairingKeyBundle::new(scope, 2, 2, *b.workspace_root_key(), *b.active_epoch_key())
                .unwrap();
        cases.push(encode_pairing_key_bundle(&unpinned).unwrap().to_vec());
        for (scope, pin, root) in [
            (scope, a.context.enrollment_record_sha256, [0; 32]),
            (scope, Sha256Digest([7; 32]), *b.workspace_root_key()),
            (
                SyncScope {
                    account_id: id(9),
                    workspace_id: id(2),
                },
                a.context.enrollment_record_sha256,
                *b.workspace_root_key(),
            ),
        ] {
            let bad = PairingKeyBundle::new(scope, 2, 2, root, *b.active_epoch_key())
                .unwrap()
                .with_enrollment_record_sha256(pin)
                .unwrap();
            cases.push(encode_pairing_key_bundle(&bad).unwrap().to_vec());
        }
        let mut noncanonical = encode_pairing_key_bundle(b).unwrap().to_vec();
        noncanonical.splice(2..3, [0x18, 2]);
        cases.push(noncanonical);
        cases.push(vec![0; MAX_BUNDLE_BYTES + 1]);
        for bad in cases {
            let mut e = Encoder::new(Vec::new());
            e.array(2)
                .unwrap()
                .bytes(&encode_pairing_key_bundle(&f.bundles[0]).unwrap())
                .unwrap()
                .bytes(&bad)
                .unwrap();
            page.envelope = wrap_secret(
                f.keys.wrapping_public_key(),
                &e.into_writer(),
                &page.aad(&a.context).unwrap(),
            )
            .unwrap();
            let raw = page.canonical_bytes().unwrap();
            let header = a
                .sign_header(digest(&raw), &f.exporter_keys)
                .unwrap()
                .canonical_bytes()
                .unwrap();
            let mut v = a.verify_header(&header).unwrap();
            let saved = v.next_page();
            assert!(v.open_next_page(&raw, &f.keys, trust).is_err());
            assert_eq!(v.next_page(), saved);
        }
        let original = TransferPage::decode(&raw).unwrap();
        let secret = f
            .keys
            .unwrap_secret(&original.envelope, &original.aad(&a.context).unwrap())
            .unwrap();
        // All authenticated header fields also participate in AEAD, even when an
        // authorized exporter signs a ciphertext prepared for a different context.
        let mut contexts = vec![a.context.clone(); 5];
        contexts[0].transfer_id = id(201);
        contexts[1].pairing_membership_successor_sha256 = Sha256Digest([9; 32]);
        contexts[2].authorizing_control_state_sha256 = Sha256Digest([9; 32]);
        contexts[3].checkpoint_sha256 = Sha256Digest([9; 32]);
        contexts[4].recipient_certificate_sha256 = Sha256Digest([9; 32]);
        for context in contexts {
            page.envelope = wrap_secret(
                f.keys.wrapping_public_key(),
                secret.expose(),
                &page.aad(&context).unwrap(),
            )
            .unwrap();
            let raw = page.canonical_bytes().unwrap();
            let header = a
                .sign_header(digest(&raw), &f.exporter_keys)
                .unwrap()
                .canonical_bytes()
                .unwrap();
            assert!(
                a.verify_header(&header)
                    .unwrap()
                    .open_next_page(&raw, &f.keys, trust)
                    .is_err()
            );
        }
    }

    #[test]
    fn historical_inventory_arithmetic_is_bounded_without_lifetime_ceiling() {
        assert_eq!(page_count(0), 0);
        assert_eq!(page_count(1), 1);
        assert_eq!(page_count(32), 1);
        assert_eq!(page_count(33), 2);
        assert_eq!(page_count(u32::MAX - 1), 134217728);
        assert_eq!(page_inventory(33, 0).unwrap(), (1, 32));
        assert_eq!(page_inventory(33, 1).unwrap(), (33, 1));
        assert!(page_inventory(33, 2).is_err());
        assert!(page_inventory(0, 0).is_err());
        assert!(page_inventory(u32::MAX - 1, u32::MAX).is_err());
    }

    fn context(last: u32) -> TransferContext {
        TransferContext {
            transfer_id: id(10),
            account_id: id(1),
            workspace_id: id(2),
            pairing_membership_successor_sha256: Sha256Digest([1; 32]),
            authorizing_control_state_sha256: Sha256Digest([2; 32]),
            recipient_device_id: id(4),
            recipient_certificate_sha256: Sha256Digest([3; 32]),
            enrollment_record_sha256: Sha256Digest([4; 32]),
            exporter_device_id: id(3),
            checkpoint_sha256: Sha256Digest([5; 32]),
            last_historical_key_epoch: last,
            page_count: page_count(last),
        }
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn id<T: std::str::FromStr>(n: u8) -> T {
        format!("018f22e2-79b0-7cc8-98c4-dc0c0c0739{n:02x}")
            .parse()
            .ok()
            .unwrap()
    }

    #[test]
    fn historical_fixed_header_and_page_canonical_hostile_inputs() {
        let keys = DeviceKeys::from_seeds([1; 32], [2; 32]);
        let c = context(33);
        let mut header = HistoricalTransferHeader {
            context: c.clone(),
            first_page_sha256: Sha256Digest([6; 32]),
            signature: Ed25519SignatureBytes([0; 64]),
        };
        header.signature = keys.sign_hosted_device_proof(&header.preimage().unwrap());
        let raw = header.canonical_bytes().unwrap();
        // Independent Python struct/UUID + cryptography Ed25519 vector.
        assert_eq!(raw.len(), 387);
        assert_eq!(
            hex(&header.preimage().unwrap()),
            "636f6e746578742d72656c61792f686973746f726963616c2d6b65792d7472616e736665722f7631000001018f22e279b07cc898c4dc0c0c07390a018f22e279b07cc898c4dc0c0c073901018f22e279b07cc898c4dc0c0c07390201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202018f22e279b07cc898c4dc0c0c07390403030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404018f22e279b07cc898c4dc0c0c073903050505050505050505050505050505050505050505050505050505050505050500000021000000020606060606060606060606060606060606060606060606060606060606060606"
        );
        assert_eq!(
            hex(&header.signature.0),
            "cf98b1313e6442399cbfa519eff2ba42436cc6711d543597789038dd0f75d8c47b5629af4aa46a2dfe445641c6c881c203b9572504aadb85cee9fe7f9f6fb804"
        );
        assert_eq!(
            hex(&digest(&raw).0),
            "d38a4d8766ad0606a5d9b2607c29234e95f58f19d1fa902448505b0b5122f011"
        );
        assert_eq!(HistoricalTransferHeader::decode(&raw).unwrap(), header);
        for end in 0..raw.len() {
            assert!(HistoricalTransferHeader::decode(&raw[..end]).is_err());
        }
        let mut bad = raw.clone();
        bad.push(0);
        assert!(HistoricalTransferHeader::decode(&bad).is_err());
        let mut bad = raw.clone();
        bad[0] ^= 1;
        assert!(HistoricalTransferHeader::decode(&bad).is_err());
        let mut bad = raw.clone();
        bad[HEADER_DOMAIN.len() + 1] = 2;
        assert!(HistoricalTransferHeader::decode(&bad).is_err());
        for offset in [2, 18, 34, 114, 194] {
            let mut bad = raw.clone();
            bad[HEADER_DOMAIN.len() + offset..HEADER_DOMAIN.len() + offset + 16].fill(0);
            assert!(HistoricalTransferHeader::decode(&bad).is_err());
        }
        let p = TransferPage {
            index: 1,
            first_key_epoch: 33,
            bundle_count: 1,
            next_page_sha256: ZERO,
            envelope: WrappedKeyEnvelope {
                ephemeral_public_key: keys.wrapping_public_key(),
                nonce: context_relay_protocol::XChaChaNonce([7; 24]),
                ciphertext: vec![8; 16],
            },
        };
        let raw = p.canonical_bytes().unwrap();
        // Independent manual canonical CBOR/X25519 wire vector; ciphertext is dummy.
        assert_eq!(
            hex(&raw),
            "a500010118210201035820000000000000000000000000000000000000000000000000000000000000000004a3005820ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59015818070707070707070707070707070707070707070707070707025008080808080808080808080808080808"
        );
        assert_eq!(
            hex(&p.aad(&c).unwrap()),
            "636f6e746578742d72656c61792f686973746f726963616c2d6b65792d706167652f7631000001018f22e279b07cc898c4dc0c0c07390a018f22e279b07cc898c4dc0c0c073901018f22e279b07cc898c4dc0c0c07390201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202018f22e279b07cc898c4dc0c0c07390403030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404018f22e279b07cc898c4dc0c0c073903050505050505050505050505050505050505050505050505050505050505050500000021000000020000000100000021000000010000000000000000000000000000000000000000000000000000000000000000"
        );

        assert_eq!(TransferPage::decode(&raw).unwrap(), p);
        for end in 0..raw.len() {
            assert!(TransferPage::decode(&raw[..end]).is_err());
        }
        for (offset, value) in [(0, 0xbf), (1, 1), (3, 0), (5, 4)] {
            let mut bad = raw.clone();
            bad[offset] = value;
            assert!(TransferPage::decode(&bad).is_err());
        }
        let mut bad = raw.clone();
        bad.splice(2..3, [0x18, 1]);
        assert!(TransferPage::decode(&bad).is_err());
        let mut bad = raw.clone();
        bad.push(0);
        assert!(TransferPage::decode(&bad).is_err());
        assert!(TransferPage::decode(&vec![0; MAX_PAGE_BYTES + 1]).is_err());
    }
}
