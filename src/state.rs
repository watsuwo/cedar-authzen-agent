//! Shared application state for the HTTP handlers (DESIGN.md §3, §10).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::Authorizer;
use cedar_policy::Schema;

/// The concrete authorizer type for this sidecar: file-backed policy provider
/// (over the S3 Files mount) and an empty entity provider (DESIGN.md §2.1).
pub type SidecarAuthorizer = Authorizer<PolicySetProvider, EntityProvider>;

/// State shared across all requests (cheaply cloneable via `Arc`).
#[derive(Clone)]
pub struct AppState {
    /// The Cedar authorizer.
    pub authorizer: Arc<SidecarAuthorizer>,
    /// The schema used to validate incoming requests (DESIGN.md §4 ③).
    pub schema: Arc<Schema>,
    /// Readiness flag: `true` once the initial load succeeded and the most
    /// recent reload (if any) also succeeded. Flipped to `false` on a failed
    /// reload so `/readyz` returns 503 (DESIGN.md §10).
    pub ready: Arc<AtomicBool>,
}
