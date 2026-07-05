use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::Authorizer;
use cedar_policy::Schema;

pub type SidecarAuthorizer = Authorizer<PolicySetProvider, EntityProvider>;

#[derive(Clone)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn new(ready: bool) -> Self {
        Self(Arc::new(AtomicBool::new(ready)))
    }

    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub authorizer: Arc<SidecarAuthorizer>,
    pub provider: Arc<PolicySetProvider>,
    pub schema: Arc<Schema>,
    pub readiness: Readiness,
}
