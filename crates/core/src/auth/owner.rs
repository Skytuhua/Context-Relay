use super::{
    HostedIdentity, HostedSession, LoginError, LoginExchange, LoginStore, SupabaseAuthClient,
};
use std::{
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// Opaque, single-use ownership of a browser login attempt.
pub struct LoginAttempt(Arc<AtomicBool>);
#[derive(Clone, Default)]
pub struct LoginCancellation(Arc<AtomicBool>);
impl LoginAttempt {
    pub fn cancellation(&self) -> LoginCancellation {
        LoginCancellation(self.0.clone())
    }
}
impl LoginCancellation {
    /// Immediately withdraws this generation; the owner performs credential cleanup.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
pub struct LogoutOutcome {
    pub local: Result<(), LoginError>,
    pub remote: Option<Result<(), LoginError>>,
}
struct State {
    generation: Arc<AtomicBool>,
    initialized: bool,
    busy: bool,
    session: Option<Arc<HostedSession>>,
}

/// One owner per daemon login slot. Call blocking methods on a blocking worker,
/// outside the vault's ordered worker. Network calls never hold the state lock.
pub struct HostedSessionOwner {
    client: Arc<SupabaseAuthClient>,
    store: Arc<dyn LoginStore>,
    state: Mutex<State>,
}
impl HostedSessionOwner {
    pub fn new(client: Arc<SupabaseAuthClient>, store: Arc<dyn LoginStore>) -> Self {
        Self {
            client,
            store,
            state: Mutex::new(State {
                generation: Arc::new(AtomicBool::new(false)),
                initialized: false,
                busy: false,
                session: None,
            }),
        }
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>, LoginError> {
        self.state.lock().map_err(|_| LoginError::Unavailable)
    }
    fn invalidate(state: &mut State) {
        state.generation.store(true, Ordering::SeqCst);
        state.generation = Arc::new(AtomicBool::new(false));
        state.initialized = true;
        state.busy = false;
        state.session = None;
    }
    /// Call before starting the loopback listener/browser flow. Supersedes old work.
    pub fn begin_login(&self) -> Result<LoginAttempt, LoginError> {
        self.begin_login_cancellable(LoginCancellation::default())
    }
    /// A queued worker must check its reservation before mutating a newer login.
    pub fn begin_login_cancellable(
        &self,
        cancellation: LoginCancellation,
    ) -> Result<LoginAttempt, LoginError> {
        let mut state = self.lock()?;
        if cancellation.0.load(Ordering::SeqCst) || Arc::ptr_eq(&cancellation.0, &state.generation)
        {
            return Err(LoginError::Canceled);
        }
        Self::invalidate(&mut state);
        state.generation = cancellation.0;
        self.store.clear()?;
        state.busy = true;
        Ok(LoginAttempt(state.generation.clone()))
    }
    pub fn cancel_login(&self, attempt: LoginAttempt) -> Result<(), LoginError> {
        self.cancel_attempt(attempt.cancellation())
    }
    pub fn cancel_attempt(&self, cancellation: LoginCancellation) -> Result<(), LoginError> {
        cancellation.cancel();
        let mut state = self.lock()?;
        if !Arc::ptr_eq(&cancellation.0, &state.generation) {
            return Err(LoginError::Canceled);
        }
        Self::invalidate(&mut state);
        self.store.clear()
    }
    pub fn complete_login(
        &self,
        attempt: LoginAttempt,
        exchange: LoginExchange,
        now: u64,
    ) -> Result<HostedIdentity, LoginError> {
        {
            let state = self.lock()?;
            if !state.busy
                || attempt.0.load(Ordering::SeqCst)
                || !Arc::ptr_eq(&attempt.0, &state.generation)
            {
                return Err(LoginError::Canceled);
            }
        }
        let started = Instant::now();
        let result = self.client.exchange(exchange, now).map(Some);
        self.finish(
            attempt.0,
            result,
            now.saturating_add(started.elapsed().as_secs()),
        )?
        .ok_or(LoginError::Unavailable)
    }
    /// Restore is allowed before login/logout, with explicit transient retries. A failed logout cannot be
    /// undone by reloading credentials that the OS refused to delete.
    pub fn restore(&self, now: u64) -> Result<Option<HostedIdentity>, LoginError> {
        let (generation, stored) = {
            let mut state = self.lock()?;
            if state.initialized {
                return Err(LoginError::Canceled);
            }
            let stored = self.store.load()?;
            state.initialized = true;
            state.busy = true;
            (state.generation.clone(), stored)
        };
        let started = Instant::now();
        let result = stored
            .as_ref()
            .map(|stored| self.client.restore(stored, now))
            .transpose();
        let result = self.finish(
            generation.clone(),
            result,
            now.saturating_add(started.elapsed().as_secs()),
        );
        if matches!(result, Err(LoginError::Unavailable)) {
            let mut state = self.lock()?;
            if Arc::ptr_eq(&generation, &state.generation) {
                state.initialized = false;
            }
        }
        result
    }
    pub fn refresh(&self, now: u64) -> Result<HostedIdentity, LoginError> {
        let (generation, session) = {
            let mut state = self.lock()?;
            if state.generation.load(Ordering::SeqCst) {
                return Err(LoginError::Canceled);
            }
            if state.busy {
                return Err(LoginError::Busy);
            }
            let session = state.session.clone().ok_or(LoginError::Denied)?;
            state.busy = true;
            (state.generation.clone(), session)
        };
        let started = Instant::now();
        let result = self.client.refresh(&session, now).map(Some);
        self.finish(
            generation,
            result,
            now.saturating_add(started.elapsed().as_secs()),
        )?
        .ok_or(LoginError::Unavailable)
    }
    fn finish(
        &self,
        generation: Arc<AtomicBool>,
        result: Result<Option<HostedSession>, LoginError>,
        now: u64,
    ) -> Result<Option<HostedIdentity>, LoginError> {
        let started = Instant::now();
        let mut state = self.lock()?;
        if !Arc::ptr_eq(&generation, &state.generation) {
            return Err(LoginError::Canceled);
        }
        state.busy = false;
        if generation.load(Ordering::SeqCst) {
            state.session = None;
            self.store.clear()?;
            return Err(LoginError::Canceled);
        }
        let result = match result {
            Err(error @ (LoginError::Denied | LoginError::Provider | LoginError::Expired)) => {
                state.session = None;
                self.store.clear()?;
                return Err(error);
            }
            other => other,
        };
        let Some(session) = result? else {
            return Ok(None);
        };
        if session.expires_at() <= now.saturating_add(started.elapsed().as_secs()) {
            state.session = None;
            self.store.clear()?;
            return Err(LoginError::Expired);
        }
        if let Err(error) = self.store.save(&session.stored_login()) {
            state.session = None;
            // A failed save may be ambiguous. Never publish it or reload it in this owner.
            self.store.clear()?;
            return Err(error);
        }
        if generation.load(Ordering::SeqCst) {
            state.session = None;
            self.store.clear()?;
            return Err(LoginError::Canceled);
        }
        if session.expires_at() <= now.saturating_add(started.elapsed().as_secs()) {
            state.session = None;
            self.store.clear()?;
            return Err(LoginError::Expired);
        }
        let identity = *session.identity();
        state.session = Some(Arc::new(session));
        Ok(Some(identity))
    }
    /// Daemon-only transport access; credentials must never be serialized to IPC.
    pub fn current_session(&self, now: u64) -> Result<Option<Arc<HostedSession>>, LoginError> {
        let state = self.lock()?;
        if state.generation.load(Ordering::SeqCst) {
            return Ok(None);
        }
        Ok(state
            .session
            .as_ref()
            .filter(|s| s.expires_at() > now)
            .cloned())
    }
    /// Local deletion and remote revocation have separate outcomes. In-memory
    /// state and pending work are invalidated even when local deletion fails.
    pub fn logout(&self) -> Result<LogoutOutcome, LoginError> {
        let (session, local) = {
            let mut state = self.lock()?;
            let session = state.session.clone();
            Self::invalidate(&mut state);
            (session, self.store.clear())
        };
        let remote = session.as_ref().map(|session| self.client.logout(session));
        Ok(LogoutOutcome { local, remote })
    }
}
