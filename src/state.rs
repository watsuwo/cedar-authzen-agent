use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::Authorizer;
use cedar_policy::Schema;

pub type PdpAuthorizer = Authorizer<PolicySetProvider, EntityProvider>;

#[derive(Clone)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn new(ready: bool) -> Self {
        Self(Arc::new(AtomicBool::new(ready)))
    }

    pub fn set_ready(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub authorizer: Arc<PdpAuthorizer>,
    pub provider: Arc<PolicySetProvider>,
    pub schema: Arc<Schema>,
    pub readiness: Readiness,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_round_trips() {
        let readiness = Readiness::new(true);
        assert!(readiness.is_ready());

        readiness.set_ready(false);
        assert!(!readiness.is_ready());
    }

    #[test]
    fn readiness_clones_share_state() {
        let readiness = Readiness::new(true);
        let clone = readiness.clone();

        clone.set_ready(false);
        assert!(!readiness.is_ready());
    }
}
