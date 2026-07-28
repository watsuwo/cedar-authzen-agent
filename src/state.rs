use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::Authorizer;
use cedar_policy::Schema;

pub type SidecarAuthorizer = Authorizer<PolicySetProvider, EntityProvider>;

/// `/readyz` が参照する準備状態。ポリシー再読み込みタスクと共有する。
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
    pub authorizer: Arc<SidecarAuthorizer>,
    pub provider: Arc<PolicySetProvider>,
    pub schema: Arc<Schema>,
    pub readiness: Readiness,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_round_trips() {
        // `/readyz` の応答を決める最小の読み書き。
        let readiness = Readiness::new(true);
        assert!(readiness.is_ready());

        readiness.set_ready(false);
        assert!(!readiness.is_ready());
    }

    #[test]
    fn readiness_clones_share_state() {
        // reload タスクと `/readyz` ハンドラは別クローンを持つ。Clone が
        // 値のコピーになっていると再読み込み失敗が readiness に反映されない。
        let readiness = Readiness::new(true);
        let clone = readiness.clone();

        clone.set_ready(false);
        assert!(!readiness.is_ready());
    }
}
