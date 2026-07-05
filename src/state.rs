//! HTTP ハンドラ間で共有するアプリケーション状態（DESIGN.md §3, §10）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::Authorizer;
use cedar_policy::Schema;

/// 本サイドカーで使う `Authorizer` の具体型。ファイルバックのポリシープロバイダ
/// （S3 Files マウント上の `PolicySetProvider`）と、空のエンティティプロバイダ
/// （`EntityProvider`）を型引数に持つ（DESIGN.md §2.1）。
pub type SidecarAuthorizer = Authorizer<PolicySetProvider, EntityProvider>;

/// readiness フラグの共有ハンドル。`AtomicBool` の生操作をここに閉じ込め、
/// 書き手（リロードタスク）と読み手（`/readyz`）は意図が明確なメソッドだけを
/// 使う（DESIGN.md §10）。
#[derive(Clone)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// 初期状態を指定して生成する。起動時ロードが成功した後に `true` で作る。
    pub fn new(ready: bool) -> Self {
        Self(Arc::new(AtomicBool::new(ready)))
    }

    /// readiness を更新する。リロードタスクが成否に応じて呼ぶ。
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    /// 現在 ready かどうか。`/readyz` が参照する。
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// 全リクエストで共有する状態（`Arc` により安価にクローンできる）。
#[derive(Clone)]
pub struct AppState {
    /// Cedar 認可器。
    pub authorizer: Arc<SidecarAuthorizer>,
    /// ポリシープロバイダ。判定ログで「効いたポリシー」の `@id` アノテーションを
    /// 解決する（`reason()` が返す内部 `PolicyId` を人間可読名に変換する）ために
    /// 認可器とは別に保持する。
    pub provider: Arc<PolicySetProvider>,
    /// 受信リクエストの検証に使うスキーマ（DESIGN.md §4 ③)。
    pub schema: Arc<Schema>,
    /// readiness フラグ。初回ロードが成功し、かつ直近のリロード（あれば）も成功
    /// していれば ready。リロード失敗時に not-ready へ倒され、`/readyz` が 503 を
    /// 返すようになる（DESIGN.md §10）。
    pub readiness: Readiness,
}
