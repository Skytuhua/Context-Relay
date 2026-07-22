use std::{cell::RefCell, rc::Rc};

use context_relay_macos_launcher_harness::{
    model::{
        GenerationId, GenerationState, MacCodeIdentity, MacCommand, MacCommandPaths,
        MacPolicyError, MacRootIdentity,
    },
    policy::{
        EntitlementSubject, EntitlementValue, GenerationDecision, GenerationJournal,
        GenerationLease, GenerationProcess, MachOInspection, ProcessOutcome, SignedGeneration,
        container_identity_bytes, execute_generation, validate_container_identity,
        validate_entitlements, validate_macho_closure,
    },
};

#[test]
fn only_the_exact_kernel_selected_code_identity_can_resume() {
    let expected = MacCodeIdentity::new(vec![0x41; 20]).unwrap();
    let mut replacement = vec![0x41; 20];
    replacement[19] = 0x42;

    assert!(expected.matches(&[0x41; 20]));
    assert!(!expected.matches(&replacement));
    assert!(MacCodeIdentity::new(Vec::new()).is_err());
    assert!(MacCodeIdentity::new(vec![0; 65]).is_err());
}

#[test]
fn generation_ids_have_an_exact_unique_lower_hex_suffix() {
    let first = GenerationId::from_nonce([0xab; 16]);
    let second = GenerationId::from_nonce([0xcd; 16]);

    assert_eq!(
        first.as_str(),
        "com.contextrelay.native-runner.abababababababababababababababab"
    );
    assert_eq!(first.as_str().len(), 63);
    assert_ne!(first, second);
    assert!(GenerationId::parse(first.as_str()).is_ok());
    assert!(GenerationId::parse("com.contextrelay.native-runner.ABAB").is_err());
    assert!(GenerationId::parse("com.contextrelay.native-runner.00").is_err());
}

#[test]
fn container_identity_is_an_opaque_versioned_bundle_token_never_a_path() {
    let id = GenerationId::from_nonce([0x2a; 16]);
    let token = container_identity_bytes(&id);
    let mut expected = b"context-relay/macos-container/v1\0".to_vec();
    expected.extend_from_slice(id.as_str().as_bytes());

    assert_eq!(token, expected);
    assert!(validate_container_identity(&id, &token).is_ok());
    assert!(validate_container_identity(&id, id.as_str().as_bytes()).is_err());
    assert!(validate_container_identity(&id, b"/Users/me/Library/Containers/x").is_err());
}

#[test]
fn root_identity_encoding_is_versioned_and_covers_aba_fields() {
    let identity = root_identity(7);
    let encoded = identity.encode();
    let frozen = MacRootIdentity::new(8, 9, 10, 11, 12, 0o040500).unwrap();
    let mutable = MacRootIdentity::new(8, 9, 10, 11, 12, 0o040700).unwrap();

    assert_eq!(MacRootIdentity::decode(&encoded).unwrap(), identity);
    assert_eq!(frozen, mutable);
    assert_eq!(frozen.encode(), mutable.encode());
    assert!(MacRootIdentity::decode(&encoded[1..]).is_err());
    assert!(MacRootIdentity::new(0, 2, 3, 4, 5, 0o040700).is_err());
    assert!(MacRootIdentity::new(1, 0, 3, 4, 5, 0o040700).is_err());
    assert!(MacRootIdentity::new(1, 2, 3, 4, 1_000_000_000, 0o040700).is_err());
    assert!(MacRootIdentity::new(1, 2, 3, 4, 5, 0o100700).is_err());
}

#[test]
fn restart_poisons_unbound_and_bound_prepared_as_well_as_active() {
    let mut unbound_prepared = GenerationLease::new(GenerationId::from_nonce([0x10; 16]));
    assert_eq!(
        unbound_prepared.recover_after_restart(),
        GenerationDecision::PersistPoisoned
    );

    let mut bound_prepared = GenerationLease::new(GenerationId::from_nonce([0x11; 16]));
    let durable_roots = (root_identity(0x12), root_identity(0x13));
    assert_ne!(durable_roots.0, durable_roots.1);
    assert_eq!(
        bound_prepared.recover_after_restart(),
        GenerationDecision::PersistPoisoned
    );

    let id = GenerationId::from_nonce([1; 16]);
    let mut lease = GenerationLease::new(id.clone());
    assert_eq!(lease.state(), GenerationState::Prepared);
    assert_eq!(lease.activate().unwrap(), GenerationDecision::PersistActive);
    assert_eq!(lease.state(), GenerationState::Active);
    assert_eq!(
        lease.recover_after_restart(),
        GenerationDecision::PersistPoisoned
    );
    assert_eq!(lease.state(), GenerationState::Poisoned);
    assert!(lease.activate().is_err());
    assert!(lease.retire().is_err());

    let mut clean = GenerationLease::new(GenerationId::from_nonce([2; 16]));
    clean.activate().unwrap();
    assert_eq!(clean.retire().unwrap(), GenerationDecision::PersistRetired);
    assert!(clean.activate().is_err());
}

#[test]
fn codesign_commands_are_closed_inside_out_and_never_use_deep_or_a_shell() {
    let paths = MacCommandPaths::new(
        "/private/context/helper.app",
        "/private/context/helper.app/Contents/MacOS/helper",
        "/private/context/helper.entitlements.plist",
    )
    .unwrap();
    let id = GenerationId::from_nonce([3; 16]);
    let sign = MacCommand::sign_generation(&paths, &id);
    assert_eq!(sign.program(), "/usr/bin/codesign");
    assert_eq!(
        sign.arguments(),
        [
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--timestamp=none",
            "--identifier",
            id.as_str(),
            "--entitlements",
            "/private/context/helper.entitlements.plist",
            "/private/context/helper.app",
        ]
    );
    let sidecar = MacCommand::sign_sidecar(
        "/private/context/helper.app/Contents/Helpers/runtime/osemgrep",
        "/private/context/sidecar.entitlements.plist",
    )
    .unwrap();
    assert_eq!(
        sidecar.arguments(),
        [
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--timestamp=none",
            "--entitlements",
            "/private/context/sidecar.entitlements.plist",
            "/private/context/helper.app/Contents/Helpers/runtime/osemgrep",
        ]
    );
    for command in [
        sidecar,
        sign,
        MacCommand::verify_strict(&paths),
        MacCommand::display_entitlements(&paths),
        MacCommand::display_identity(&paths),
    ] {
        assert_eq!(command.program(), "/usr/bin/codesign");
        assert!(!command.arguments().contains(&"--deep"));
        assert!(!command.arguments().iter().any(|arg| arg.contains("sh -c")));
    }
}

#[test]
fn helper_and_sidecars_have_only_their_exact_sandbox_entitlements() {
    assert!(
        validate_entitlements(
            EntitlementSubject::Helper,
            &[(
                "com.apple.security.app-sandbox",
                EntitlementValue::Boolean(true),
            )]
        )
        .is_ok()
    );
    assert!(validate_entitlements(EntitlementSubject::Helper, &[]).is_err());
    assert!(
        validate_entitlements(
            EntitlementSubject::Helper,
            &[
                (
                    "com.apple.security.app-sandbox",
                    EntitlementValue::Boolean(true),
                ),
                (
                    "com.apple.security.network.client",
                    EntitlementValue::Boolean(true),
                ),
            ]
        )
        .is_err()
    );
    assert!(
        validate_entitlements(
            EntitlementSubject::Helper,
            &[(
                "com.apple.security.app-sandbox",
                EntitlementValue::Boolean(false),
            )]
        )
        .is_err()
    );
    let inherited = [
        (
            "com.apple.security.app-sandbox",
            EntitlementValue::Boolean(true),
        ),
        (
            "com.apple.security.inherit",
            EntitlementValue::Boolean(true),
        ),
    ];
    assert!(validate_entitlements(EntitlementSubject::Sidecar, &inherited).is_ok());
    assert!(validate_entitlements(EntitlementSubject::Sidecar, &[]).is_err());
    assert!(
        validate_entitlements(
            EntitlementSubject::Sidecar,
            &[(
                "com.apple.security.inherit",
                EntitlementValue::Boolean(true),
            )]
        )
        .is_err()
    );
}

#[test]
fn every_expected_macho_must_be_signed_and_inspected_without_extras() {
    let expected = ["helper", "gitleaks", "osemgrep", "rulesync"];
    let valid = expected
        .iter()
        .map(|path| MachOInspection {
            relative_path: (*path).into(),
            signed: true,
            entitlements: if *path == "helper" {
                vec![(
                    "com.apple.security.app-sandbox".into(),
                    EntitlementValue::Boolean(true),
                )]
            } else {
                vec![
                    (
                        "com.apple.security.app-sandbox".into(),
                        EntitlementValue::Boolean(true),
                    ),
                    (
                        "com.apple.security.inherit".into(),
                        EntitlementValue::Boolean(true),
                    ),
                ]
            },
        })
        .collect::<Vec<_>>();
    assert!(validate_macho_closure("helper", &expected, &valid).is_ok());

    let mut unsigned = valid.clone();
    unsigned[2].signed = false;
    assert!(validate_macho_closure("helper", &expected, &unsigned).is_err());

    let mut extra = valid;
    extra.push(MachOInspection {
        relative_path: "surprise".into(),
        signed: true,
        entitlements: vec![],
    });
    assert!(validate_macho_closure("helper", &expected, &extra).is_err());
}

#[test]
fn suspended_verified_spawn_and_bound_roots_precede_active_resume_and_input() {
    let events = events();
    let journal = FakeJournal::new(events.clone());
    let mut process = FakeProcess::new(events.clone(), ProcessOutcome::Completed("ok"));
    let generation = signed_generation(0x41);

    assert_eq!(
        execute_generation(&journal, &generation, &mut process).unwrap(),
        "ok"
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:container-bound",
            "process:container-authority-confirmed",
            "journal:active",
            "process:resume-input",
            "process:wait",
            "process:terminate-group",
            "journal:retired",
            "process:cleanup-terminal",
        ]
    );
}

#[test]
fn failed_root_binding_never_activates_or_resumes_the_child() {
    let events = events();
    let journal = FakeJournal::failing_binding(events.clone());
    let mut process = FakeProcess::new(events.clone(), ProcessOutcome::Completed("unused"));

    assert_eq!(
        execute_generation(&journal, &signed_generation(0x40), &mut process).unwrap_err(),
        MacPolicyError::JournalFailure
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:container-bound",
            "journal:poisoned",
            "process:terminate-group",
            "process:cleanup-terminal",
        ]
    );
}

#[test]
fn failed_active_transition_reaps_the_suspended_child_without_resuming() {
    let events = events();
    let journal = FakeJournal::failing_activation(events.clone());
    let mut process = FakeProcess::new(events.clone(), ProcessOutcome::Completed("unused"));

    assert_eq!(
        execute_generation(&journal, &signed_generation(0x3f), &mut process).unwrap_err(),
        MacPolicyError::JournalFailure
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:container-bound",
            "process:container-authority-confirmed",
            "journal:active",
            "journal:poisoned",
            "process:terminate-group",
            "process:cleanup-terminal",
        ]
    );
}

#[test]
fn failed_suspended_spawn_is_poisoned_and_exact_live_roots_are_cleaned() {
    let events = events();
    let journal = FakeJournal::new(events.clone());
    let mut process =
        FakeProcess::failing_spawn(events.clone(), ProcessOutcome::Completed("unused"));

    assert_eq!(
        execute_generation(&journal, &signed_generation(0x3e), &mut process).unwrap_err(),
        MacPolicyError::ProcessFailed
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:poisoned",
            "process:terminate-group",
            "process:cleanup-terminal",
        ]
    );
}

#[test]
fn failed_pre_resume_termination_is_poisoned_but_never_cleaned() {
    let events = events();
    let journal = FakeJournal::failing_binding(events.clone());
    let mut process =
        FakeProcess::failing_first_termination(events.clone(), ProcessOutcome::Completed("unused"));

    assert_eq!(
        execute_generation(&journal, &signed_generation(0x3d), &mut process).unwrap_err(),
        MacPolicyError::ProcessFailed
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:container-bound",
            "journal:poisoned",
            "process:terminate-group",
        ]
    );
}

#[test]
fn clean_exit_group_is_terminated_even_if_retirement_journaling_fails() {
    let events = events();
    let journal = FakeJournal::failing_retirement(events.clone());
    let mut process = FakeProcess::new(events.clone(), ProcessOutcome::Completed("ok"));
    let generation = signed_generation(0x42);

    assert_eq!(
        execute_generation(&journal, &generation, &mut process).unwrap_err(),
        MacPolicyError::JournalFailure
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:container-bound",
            "process:container-authority-confirmed",
            "journal:active",
            "process:resume-input",
            "process:wait",
            "process:terminate-group",
            "journal:retired",
        ]
    );
}

#[test]
fn clean_exit_is_poisoned_when_group_termination_cannot_be_verified() {
    let events = events();
    let journal = FakeJournal::new(events.clone());
    let mut process =
        FakeProcess::failing_first_termination(events.clone(), ProcessOutcome::Completed("ok"));
    let generation = signed_generation(0x43);

    assert_eq!(
        execute_generation(&journal, &generation, &mut process).unwrap_err(),
        MacPolicyError::ProcessFailed
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:container-bound",
            "process:container-authority-confirmed",
            "journal:active",
            "process:resume-input",
            "process:wait",
            "process:terminate-group",
            "journal:poisoned",
            "process:terminate-group",
            "process:cleanup-terminal",
        ]
    );
}

#[test]
fn abnormal_exit_is_durably_poisoned_before_the_original_group_is_signaled() {
    let events = events();
    let journal = FakeJournal::new(events.clone());
    let mut process = FakeProcess::new(
        events.clone(),
        ProcessOutcome::<()>::Abnormal(MacPolicyError::ProcessTimedOut),
    );
    let generation = signed_generation(0x52);

    assert_eq!(
        execute_generation(&journal, &generation, &mut process).unwrap_err(),
        MacPolicyError::ProcessTimedOut
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:container-bound",
            "process:container-authority-confirmed",
            "journal:active",
            "process:resume-input",
            "process:wait",
            "journal:poisoned",
            "process:terminate-group",
            "process:cleanup-terminal",
        ]
    );
}

#[test]
fn cleanup_runs_only_after_group_absence_and_a_durable_terminal_state() {
    let events = events();
    let journal = FakeJournal::new(events.clone());
    let mut process =
        FakeProcess::failing_cleanup(events.clone(), ProcessOutcome::Completed("unused"));

    assert_eq!(
        execute_generation(&journal, &signed_generation(0x61), &mut process).unwrap_err(),
        MacPolicyError::BundleIo
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            "process:spawn-suspended-verified",
            "journal:container-bound",
            "process:container-authority-confirmed",
            "journal:active",
            "process:resume-input",
            "process:wait",
            "process:terminate-group",
            "journal:retired",
            "process:cleanup-terminal",
        ]
    );
}

fn events() -> Rc<RefCell<Vec<&'static str>>> {
    Rc::new(RefCell::new(Vec::new()))
}

fn signed_generation(byte: u8) -> SignedGeneration {
    SignedGeneration::new(
        GenerationId::from_nonce([byte; 16]),
        [byte; 32],
        root_identity(byte),
    )
}

fn root_identity(byte: u8) -> MacRootIdentity {
    MacRootIdentity::new(
        u64::from(byte) + 1,
        u64::from(byte) + 2,
        u32::from(byte) + 3,
        i64::from(byte) + 4,
        u32::from(byte) + 5,
        0o040500,
    )
    .unwrap()
}

struct FakeJournal {
    events: Rc<RefCell<Vec<&'static str>>>,
    fail_binding: bool,
    fail_activation: bool,
    fail_retirement: bool,
}

impl FakeJournal {
    fn new(events: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self {
            events,
            fail_binding: false,
            fail_activation: false,
            fail_retirement: false,
        }
    }

    fn failing_retirement(events: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self {
            events,
            fail_binding: false,
            fail_activation: false,
            fail_retirement: true,
        }
    }

    fn failing_binding(events: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self {
            events,
            fail_binding: true,
            fail_activation: false,
            fail_retirement: false,
        }
    }

    fn failing_activation(events: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self {
            events,
            fail_binding: false,
            fail_activation: true,
            fail_retirement: false,
        }
    }
}

impl GenerationJournal for FakeJournal {
    fn reserve(&self, _id: &GenerationId) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn bind_guardian(&self, _id: &GenerationId, _pgid: i32) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn bind_bundle_root(
        &self,
        _id: &GenerationId,
        _bundle: &MacRootIdentity,
    ) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn finalize(&self, _generation: &SignedGeneration) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn bind_container_root(
        &self,
        _id: &GenerationId,
        _container: &MacRootIdentity,
    ) -> Result<(), MacPolicyError> {
        self.events.borrow_mut().push("journal:container-bound");
        if self.fail_binding {
            return Err(MacPolicyError::JournalFailure);
        }
        Ok(())
    }

    fn transition(
        &self,
        _id: &GenerationId,
        _from: GenerationState,
        to: GenerationState,
    ) -> Result<(), MacPolicyError> {
        self.events.borrow_mut().push(match to {
            GenerationState::Active => "journal:active",
            GenerationState::Retired => "journal:retired",
            GenerationState::Poisoned => "journal:poisoned",
            GenerationState::Prepared => panic!("invalid target state"),
        });
        if to == GenerationState::Retired && self.fail_retirement {
            return Err(MacPolicyError::JournalFailure);
        }
        if to == GenerationState::Active && self.fail_activation {
            return Err(MacPolicyError::JournalFailure);
        }
        Ok(())
    }

    fn poison_interrupted_after_restart(&self) -> Result<(), MacPolicyError> {
        Ok(())
    }
}

struct FakeProcess<T> {
    events: Rc<RefCell<Vec<&'static str>>>,
    outcome: Option<ProcessOutcome<T>>,
    spawn_failure: bool,
    termination_failures: usize,
    cleanup_failures: usize,
}

impl<T> FakeProcess<T> {
    fn new(events: Rc<RefCell<Vec<&'static str>>>, outcome: ProcessOutcome<T>) -> Self {
        Self {
            events,
            outcome: Some(outcome),
            spawn_failure: false,
            termination_failures: 0,
            cleanup_failures: 0,
        }
    }

    fn failing_first_termination(
        events: Rc<RefCell<Vec<&'static str>>>,
        outcome: ProcessOutcome<T>,
    ) -> Self {
        Self {
            events,
            outcome: Some(outcome),
            spawn_failure: false,
            termination_failures: 1,
            cleanup_failures: 0,
        }
    }

    fn failing_spawn(events: Rc<RefCell<Vec<&'static str>>>, outcome: ProcessOutcome<T>) -> Self {
        Self {
            events,
            outcome: Some(outcome),
            spawn_failure: true,
            termination_failures: 0,
            cleanup_failures: 0,
        }
    }

    fn failing_cleanup(events: Rc<RefCell<Vec<&'static str>>>, outcome: ProcessOutcome<T>) -> Self {
        Self {
            events,
            outcome: Some(outcome),
            spawn_failure: false,
            termination_failures: 0,
            cleanup_failures: 1,
        }
    }
}

impl<T> GenerationProcess for FakeProcess<T> {
    type Output = T;

    fn spawn_suspended(&mut self) -> Result<MacRootIdentity, MacPolicyError> {
        self.events
            .borrow_mut()
            .push("process:spawn-suspended-verified");
        if self.spawn_failure {
            return Err(MacPolicyError::ProcessFailed);
        }
        Ok(root_identity(0xee))
    }

    fn confirm_container_bound(&mut self) {
        self.events
            .borrow_mut()
            .push("process:container-authority-confirmed");
    }

    fn resume_and_send_input(&mut self) -> Result<(), MacPolicyError> {
        self.events.borrow_mut().push("process:resume-input");
        Ok(())
    }

    fn wait(&mut self) -> ProcessOutcome<Self::Output> {
        self.events.borrow_mut().push("process:wait");
        self.outcome.take().unwrap()
    }

    fn terminate_original_group(&mut self) -> Result<(), MacPolicyError> {
        self.events.borrow_mut().push("process:terminate-group");
        if self.termination_failures > 0 {
            self.termination_failures -= 1;
            return Err(MacPolicyError::ProcessFailed);
        }
        Ok(())
    }

    fn cleanup_terminal(&mut self) -> Result<(), MacPolicyError> {
        self.events.borrow_mut().push("process:cleanup-terminal");
        if self.cleanup_failures > 0 {
            self.cleanup_failures -= 1;
            return Err(MacPolicyError::BundleIo);
        }
        Ok(())
    }
}
