use context_relay_protocol::{
    ConnectionCheckPhase as Phase, ConnectionCheckStartParams, ConnectionCheckStatus,
    DecimalTimestamp, HarnessId, MemoryRecord, OperationId, ProjectId, ScopeRef,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// One ephemeral check per daemon. No record content or historical read log is retained.
pub(super) struct ConnectionCheck {
    pub status: ConnectionCheckStatus,
    started: Instant,
}
impl ConnectionCheck {
    pub fn start(params: ConnectionCheckStartParams) -> Self {
        Self {
            status: ConnectionCheckStatus {
                check_id: OperationId::new(uuid::Uuid::now_v7()).expect("UUIDv7"),
                selection: params.selection,
                memory_id: params.memory_id,
                expected_revision: params.expected_revision,
                phase: Phase::Waiting,
                expires_in_seconds: 300,
                verified_at: None,
            },
            started: Instant::now(),
        }
    }
    pub fn refresh(&mut self, memory: Option<&MemoryRecord>) {
        if matches!(self.status.phase, Phase::Waiting | Phase::Verified)
            && !memory.is_some_and(|memory| self.matches(memory))
        {
            self.status.phase = Phase::Invalidated;
            self.status.verified_at = None;
        }
        self.tick();
    }
    fn tick(&mut self) {
        let elapsed = self.started.elapsed();
        if self.status.phase == Phase::Waiting && elapsed >= Duration::from_secs(300) {
            self.status.phase = Phase::Expired;
        }
        self.status.expires_in_seconds = if self.status.phase == Phase::Waiting {
            300 - elapsed.as_secs().min(300) as u32
        } else {
            0
        };
    }
    fn matches(&self, memory: &MemoryRecord) -> bool {
        memory.id == self.status.memory_id
            && memory.revision == self.status.expected_revision
            && !memory.archived
            && matches!(memory.scope, ScopeRef::Project {project_id} if Some(project_id) == self.status.selection.project_id)
    }
    pub fn observe(
        &mut self,
        harness: HarnessId,
        project: Option<ProjectId>,
        memory: &MemoryRecord,
    ) {
        self.tick();
        if self.status.phase == Phase::Waiting
            && harness == self.status.selection.harness
            && project == self.status.selection.project_id
            && self.matches(memory)
        {
            let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                return;
            };
            let Ok(ms) = u64::try_from(now.as_millis()) else {
                return;
            };
            self.status.phase = Phase::Verified;
            self.status.verified_at = Some(DecimalTimestamp(ms));
            self.status.expires_in_seconds = 0;
        }
    }
    pub fn cancel(&mut self) {
        self.status.phase = Phase::Canceled;
        self.status.verified_at = None;
        self.status.expires_in_seconds = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (ConnectionCheck, MemoryRecord) {
        let outputs: serde_json::Value = serde_json::from_str(include_str!(
            "../../protocol/tests/fixtures/mcp-output-valid.json"
        ))
        .unwrap();
        let mut memory: MemoryRecord =
            serde_json::from_value(outputs["context_relay_remember"]["memory"].clone()).unwrap();
        let project = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f".parse().unwrap();
        memory.scope = ScopeRef::Project {
            project_id: project,
        };
        let check = ConnectionCheck::start(ConnectionCheckStartParams {
            selection: context_relay_protocol::HarnessParams {
                harness: HarnessId::Codex,
                project_id: Some(project),
                hermes_profile: None,
            },
            memory_id: memory.id,
            expected_revision: memory.revision,
        });
        (check, memory)
    }
    #[test]
    fn connection_check_expired_read_cannot_verify() {
        let (mut check, memory) = fixture();
        check.started = Instant::now() - Duration::from_secs(301);
        check.observe(HarnessId::Codex, check.status.selection.project_id, &memory);
        assert_eq!(check.status.phase, Phase::Expired);
        assert_eq!(check.status.expires_in_seconds, 0);
        assert!(check.status.verified_at.is_none());
    }
    #[test]
    fn connection_check_changed_or_archived_note_invalidates_even_verified_receipt() {
        for archive in [false, true] {
            let (mut check, mut memory) = fixture();
            check.observe(HarnessId::Codex, check.status.selection.project_id, &memory);
            assert_eq!(check.status.phase, Phase::Verified);
            if archive {
                memory.archived = true;
            } else {
                memory.revision = OperationId::new(uuid::Uuid::now_v7()).unwrap();
            }
            check.refresh(Some(&memory));
            assert_eq!(check.status.phase, Phase::Invalidated);
            assert!(check.status.verified_at.is_none());
            check.observe(HarnessId::Codex, check.status.selection.project_id, &memory);
            assert_eq!(check.status.phase, Phase::Invalidated);
        }
    }
    #[test]
    fn connection_check_wrong_revision_or_note_does_not_verify() {
        let (mut check, mut memory) = fixture();
        memory.revision = OperationId::new(uuid::Uuid::now_v7()).unwrap();
        check.observe(HarnessId::Codex, check.status.selection.project_id, &memory);
        assert_eq!(check.status.phase, Phase::Waiting);
        memory.revision = check.status.expected_revision;
        memory.id = context_relay_protocol::MemoryId::new(uuid::Uuid::now_v7()).unwrap();
        check.observe(HarnessId::Codex, check.status.selection.project_id, &memory);
        assert_eq!(check.status.phase, Phase::Waiting);
    }
}
