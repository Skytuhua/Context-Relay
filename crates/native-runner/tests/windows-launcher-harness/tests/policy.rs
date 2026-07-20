#![cfg(windows)]

use std::{cell::RefCell, io::Cursor, rc::Rc};

use context_relay_windows_launcher_harness::windows::{
    CreateProfileOutcome, LaunchBackend, LaunchError, LaunchSequence, LeaseState, ProfileApi,
    ProfileIdentity, ProfileJournal, ProfileMoniker, SecurityAttributePlan,
    cleanup_profile_after_durable_outcome, create_fresh_profile, drain_bounded, recover_profile,
};

#[test]
fn moniker_is_fixed_namespace_plus_exact_lower_hex_nonce() {
    let moniker = ProfileMoniker::from_nonce([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);

    assert_eq!(
        moniker.as_str(),
        "context-relay.native.00112233445566778899aabbccddeeff"
    );
    assert!(moniker.as_str().len() <= 64);
}

#[test]
fn fresh_profile_is_durably_reserved_before_os_creation() {
    let events = events();
    let mut api = FakeProfileApi::new(events.clone(), CreateProfileOutcome::Created);
    let mut journal = FakeJournal::new(events.clone());

    let lease = create_fresh_profile(&mut api, &mut journal, [0x5a; 16]).unwrap();

    assert_eq!(lease.state(), LeaseState::Created);
    assert_eq!(
        events.borrow().as_slice(),
        [
            "api:derive",
            "journal:reserve",
            "api:create",
            "journal:created"
        ]
    );
}

#[test]
fn fresh_existing_profile_is_a_collision_even_after_reservation() {
    let events = events();
    let mut api = FakeProfileApi::new(events.clone(), CreateProfileOutcome::AlreadyExists);
    let mut journal = FakeJournal::new(events.clone());

    let error = create_fresh_profile(&mut api, &mut journal, [0x33; 16]).unwrap_err();

    assert_eq!(error, LaunchError::ProfileCollision);
    assert_eq!(
        events.borrow().as_slice(),
        ["api:derive", "journal:reserve", "api:create"]
    );
}

#[test]
fn recovery_accepts_only_the_exact_pending_moniker_and_sid() {
    let events = events();
    let mut api = FakeProfileApi::new(events.clone(), CreateProfileOutcome::Created);
    let mut journal = FakeJournal::new(events.clone());
    let exact = create_fresh_profile(&mut api, &mut journal, [0x77; 16]).unwrap();

    assert_eq!(recover_profile(&mut api, &exact).unwrap(), exact);

    api.derived_sid = "S-1-15-2-999999".into();
    assert_eq!(
        recover_profile(&mut api, &exact).unwrap_err(),
        LaunchError::ProfileIdentityMismatch
    );
}

#[test]
fn profile_cleanup_is_journaled_before_delete_and_rejects_a_stale_lease() {
    let events = events();
    let mut api = FakeProfileApi::new(events.clone(), CreateProfileOutcome::Created);
    let mut journal = FakeJournal::new(events.clone());
    let lease = create_fresh_profile(&mut api, &mut journal, [0x19; 16]).unwrap();
    events.borrow_mut().clear();

    cleanup_profile_after_durable_outcome(&mut api, &mut journal, &lease).unwrap();
    assert_eq!(
        cleanup_profile_after_durable_outcome(&mut api, &mut journal, &lease),
        Err(LaunchError::JournalFailure)
    );

    assert_eq!(
        events.borrow().as_slice(),
        ["journal:cleanup", "api:delete", "journal:deleted"]
    );
}

#[test]
fn security_attributes_are_exactly_zero_capability_and_pipe_only() {
    let plan = SecurityAttributePlan::new(0x1000, [0x20, 0x24, 0x28]).unwrap();

    assert_eq!(plan.attribute_count(), 2);
    assert_eq!(plan.appcontainer_sid(), 0x1000);
    assert_eq!(plan.capabilities_ptr(), 0);
    assert_eq!(plan.capability_count(), 0);
    assert_eq!(plan.reserved(), 0);
    assert_eq!(plan.inherited_handles(), &[0x20, 0x24, 0x28]);
}

#[test]
fn security_attributes_reject_null_sid_or_duplicate_pipe_handles() {
    assert_eq!(
        SecurityAttributePlan::new(0, [0x20, 0x24, 0x28]).unwrap_err(),
        LaunchError::InvalidSecurityPlan
    );
    assert_eq!(
        SecurityAttributePlan::new(0x1000, [0x20, 0x20, 0x28]).unwrap_err(),
        LaunchError::InvalidSecurityPlan
    );
}

#[test]
fn launch_typestate_orders_suspend_job_attestation_then_exact_resume() {
    let events = events();
    let backend = FakeLaunchBackend::new(events.clone(), 1);

    let running = LaunchSequence::new(backend, "S-1-15-2-424242")
        .create_suspended()
        .unwrap()
        .bind_kill_on_close_job()
        .unwrap()
        .attest_zero_capability_token()
        .unwrap()
        .resume_once()
        .unwrap();
    drop(running);

    assert_eq!(
        events.borrow().as_slice(),
        [
            "create:suspended",
            "job:bind",
            "token:attest",
            "thread:resume"
        ]
    );
}

#[test]
fn resume_rejects_every_previous_suspend_count_except_one() {
    for count in [0, 2, u32::MAX] {
        let events = events();
        let backend = FakeLaunchBackend::new(events.clone(), count);
        let attested = LaunchSequence::new(backend, "S-1-15-2-424242")
            .create_suspended()
            .unwrap()
            .bind_kill_on_close_job()
            .unwrap()
            .attest_zero_capability_token()
            .unwrap();

        assert_eq!(
            attested.resume_once().unwrap_err(),
            LaunchError::ResumeFailed
        );
        assert_eq!(events.borrow().last().copied(), Some("drop:terminate"));
    }
}

#[test]
fn bounded_drain_accepts_exact_limit_and_rejects_limit_plus_one() {
    assert_eq!(drain_bounded(Cursor::new(b"1234"), 4).unwrap(), b"1234");
    assert_eq!(
        drain_bounded(Cursor::new(b"12345"), 4).unwrap_err(),
        LaunchError::PipeLimitExceeded
    );
}

fn events() -> Rc<RefCell<Vec<&'static str>>> {
    Rc::new(RefCell::new(Vec::new()))
}

struct FakeProfileApi {
    events: Rc<RefCell<Vec<&'static str>>>,
    create_outcome: CreateProfileOutcome,
    derived_sid: String,
}

impl FakeProfileApi {
    fn new(events: Rc<RefCell<Vec<&'static str>>>, create_outcome: CreateProfileOutcome) -> Self {
        Self {
            events,
            create_outcome,
            derived_sid: "S-1-15-2-424242".into(),
        }
    }
}

impl ProfileApi for FakeProfileApi {
    fn derive_identity(
        &mut self,
        moniker: &ProfileMoniker,
    ) -> Result<ProfileIdentity, LaunchError> {
        self.events.borrow_mut().push("api:derive");
        ProfileIdentity::from_derived(moniker.clone(), &self.derived_sid)
    }

    fn create_profile(
        &mut self,
        _identity: &ProfileIdentity,
    ) -> Result<CreateProfileOutcome, LaunchError> {
        self.events.borrow_mut().push("api:create");
        Ok(self.create_outcome)
    }

    fn delete_profile(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.events.borrow_mut().push("api:delete");
        Ok(())
    }
}

struct FakeJournal {
    events: Rc<RefCell<Vec<&'static str>>>,
    created: bool,
}

impl FakeJournal {
    fn new(events: Rc<RefCell<Vec<&'static str>>>) -> Self {
        Self {
            events,
            created: false,
        }
    }
}

impl ProfileJournal for FakeJournal {
    fn reserve(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.events.borrow_mut().push("journal:reserve");
        Ok(())
    }

    fn mark_created(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.created = true;
        self.events.borrow_mut().push("journal:created");
        Ok(())
    }

    fn attest_created(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.created
            .then_some(())
            .ok_or(LaunchError::JournalFailure)
    }

    fn mark_cleanup_pending(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.created = false;
        self.events.borrow_mut().push("journal:cleanup");
        Ok(())
    }

    fn mark_deleted(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.events.borrow_mut().push("journal:deleted");
        Ok(())
    }
}

struct FakeLaunchBackend {
    events: Rc<RefCell<Vec<&'static str>>>,
    previous_suspend_count: u32,
    child_created: bool,
    resumed: bool,
}

impl FakeLaunchBackend {
    fn new(events: Rc<RefCell<Vec<&'static str>>>, previous_suspend_count: u32) -> Self {
        Self {
            events,
            previous_suspend_count,
            child_created: false,
            resumed: false,
        }
    }
}

impl LaunchBackend for FakeLaunchBackend {
    fn create_suspended(&mut self) -> Result<(), LaunchError> {
        self.events.borrow_mut().push("create:suspended");
        self.child_created = true;
        Ok(())
    }

    fn bind_kill_on_close_job(&mut self) -> Result<(), LaunchError> {
        self.events.borrow_mut().push("job:bind");
        Ok(())
    }

    fn attest_zero_capability_token(&mut self, sid: &str) -> Result<(), LaunchError> {
        assert_eq!(sid, "S-1-15-2-424242");
        self.events.borrow_mut().push("token:attest");
        Ok(())
    }

    fn resume_thread(&mut self) -> Result<u32, LaunchError> {
        self.events.borrow_mut().push("thread:resume");
        if self.previous_suspend_count == 1 {
            self.resumed = true;
        }
        Ok(self.previous_suspend_count)
    }
}

impl Drop for FakeLaunchBackend {
    fn drop(&mut self) {
        if self.child_created && !self.resumed {
            self.events.borrow_mut().push("drop:terminate");
        }
    }
}
