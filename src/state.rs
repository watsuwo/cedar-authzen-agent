//! HTTP ハンドラ間で共有するアプリケーション状態（DESIGN.md §3, §10）。

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::Authorizer;
use cedar_policy::Schema;

/// 本サイドカーで使う `Authorizer` の具体型。ファイルバックのポリシープロバイダ
/// （S3 Files マウント上の `PolicySetProvider`）と、空のエンティティプロバイダ
/// （`EntityProvider`）を型引数に持つ（DESIGN.md §2.1）。
pub type SidecarAuthorizer = Authorizer<PolicySetProvider, EntityProvider>;

/// 全リクエストで共有する状態（`Arc` により安価にクローンできる）。
#[derive(Clone)]
pub struct AppState {
    /// Cedar 認可器。
    pub authorizer: Arc<SidecarAuthorizer>,
    /// 受信リクエストの検証に使うスキーマ（DESIGN.md §4 ③）。
    pub schema: Arc<Schema>,
    /// readiness フラグ。初回ロードが成功し、かつ直近のリロード（あれば）も成功
    /// していれば `true`。リロード失敗時に `false` へ倒され、`/readyz` が 503 を
    /// 返すようになる（DESIGN.md §10）。
    pub ready: Arc<AtomicBool>,
}
