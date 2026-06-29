//! OpenID AuthZEN Authorization API（Access Evaluation とディスカバリメタデータ）
//! の serde 型定義。<https://openid.github.io/authzen/> および DESIGN.md §2 を参照。

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Access Evaluation のリクエストボディ（`POST /access/v1/evaluation`）。
///
/// `subject`・`action`・`resource` は必須、`context` は任意。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationRequest {
    /// アクセスを要求する主体（Cedar の principal に対応）。
    pub subject: Subject,
    /// 試みられているアクション（Cedar の action に対応）。
    pub action: Action,
    /// アクセス対象のリソース（Cedar の resource に対応）。
    pub resource: Resource,
    /// 環境属性。Cedar の `Context` に対応づける（DESIGN.md §2.1）。
    #[serde(default)]
    pub context: Option<Value>,
}

/// AuthZEN Subject: `type` と `id` は必須、`properties` は任意。
///
/// `properties` はアイデンティティ属性（例: `user_type`, `department`）を運び、
/// Cedar の principal エンティティ属性として注入される（DESIGN.md §2.1）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subject {
    /// subject の型。Cedar のエンティティ型名としてそのまま使う。
    #[serde(rename = "type")]
    pub entity_type: String,
    /// subject の id。Cedar のエンティティ id としてそのまま使う。
    pub id: String,
    /// subject の属性。Cedar の principal エンティティ属性に対応づける。
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// AuthZEN Resource: `type` と `id` は必須、`properties` は任意。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    /// resource の型。Cedar のエンティティ型名としてそのまま使う。
    #[serde(rename = "type")]
    pub entity_type: String,
    /// resource の id。Cedar のエンティティ id としてそのまま使う。
    pub id: String,
    /// resource の属性。Cedar の resource エンティティ属性に対応づける。
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// AuthZEN Action: `name` は必須、`properties` は任意。
///
/// Cedar のアクションエンティティ型は常に `Action` で、`name` がアクション id に
/// なる。受け付けるアクションの集合はここにハードコードせず、Cedar スキーマが
/// 規定する（DESIGN.md §2.1）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    /// アクション名。Cedar の `Action` エンティティ id としてそのまま使う。
    pub name: String,
    /// アクション属性。仕様準拠のため受理するが、評価には使わない。
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// Access Evaluation のレスポンスボディ。
///
/// `decision: true` = Cedar の `Allow`（通常ログイン許可、外部認証は強制しない）、
/// `decision: false` = Cedar の `Deny`（`forbid` が一致 → 外部認証を強制）。
/// DESIGN.md §2.1 を参照。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationResponse {
    /// 真偽値の認可判定。
    pub decision: bool,
}

impl EvaluationResponse {
    /// 判定のみを持つレスポンスを生成する。
    pub fn new(decision: bool) -> Self {
        Self { decision }
    }
}

/// `GET /.well-known/authzen-configuration` が返す PDP メタデータ。
///
/// MVP では Access Evaluation 機能のみを広告する（DESIGN.md §2）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzenConfiguration {
    /// この PDP のベース URL（この文書を取得した URL と一致する必要がある）。
    pub policy_decision_point: String,
    /// Access Evaluation エンドポイントの絶対 URL。
    pub access_evaluation_endpoint: String,
}

/// 4xx/5xx レスポンスで返す最小限のエラーボディ（DESIGN.md §8）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    /// 短く安定したエラーコード（例: `invalid_request`）。
    pub error: String,
    /// 人間可読な詳細メッセージ。
    pub message: String,
}

impl ErrorBody {
    /// コードと詳細メッセージからエラーボディを生成する。
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }
}
