//! AuthZEN の [`EvaluationRequest`] を、スキーマ検証済みの Cedar [`Request`] と
//! リクエスト時 [`Entities`] のペアに変換する（DESIGN.md §2.1, §4 ③）。
//!
//! - `subject.type`/`id` -> Cedar principal（`User::"<id>"`）
//! - `action.name`       -> Cedar action（`Action::"<name>"`）
//! - `resource.type`/`id`-> Cedar resource（`Client::"<id>"`）
//! - `subject.properties`-> principal エンティティの属性（アイデンティティ ABAC）
//! - `context`           -> Cedar `Context`（環境属性）
//!
//! 全入力を Cedar の [`Schema`] に対して検証する。未知の型・アクション・属性は
//! 拒否し、呼び出し側（ハンドラ）が HTTP 400 にマッピングする。

use std::str::FromStr;

use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, Request, Schema,
};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::authzen::EvaluationRequest;

/// AuthZEN のアクションに用いる Cedar エンティティ型（Cedar ではアクションは
/// 必ず `Action::"<name>"` という固定の型を持つ）。
const ACTION_TYPE: &str = "Action";

/// AuthZEN リクエストを Cedar 入力へ変換する過程で生じるエラー。
///
/// いずれのバリアントもハンドラで HTTP 400（bad request）にマッピングされる。
#[derive(Debug, Error)]
pub enum ConversionError {
    /// `type`/`id`/`name` を Cedar のエンティティ uid にパースできなかった。
    #[error("invalid entity reference: {0}")]
    InvalidEntity(String),
    /// AuthZEN の `context` がスキーマ検証に失敗した。
    #[error("invalid context: {0}")]
    InvalidContext(String),
    /// `properties` がエンティティ属性としてのスキーマ検証に失敗した。
    #[error("invalid properties: {0}")]
    InvalidProperties(String),
    /// 組み立てたリクエストがスキーマ検証に失敗した（未知のアクション・型など）。
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

impl ConversionError {
    /// JSON エラーボディ用の安定したエラーコード（DESIGN.md §8）。
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidEntity(_) => "invalid_entity",
            Self::InvalidContext(_) => "invalid_context",
            Self::InvalidProperties(_) => "invalid_properties",
            Self::InvalidRequest(_) => "invalid_request",
        }
    }
}

/// `type` + `id` のペアから Cedar のエンティティ uid を組み立てる（値はそのまま使う）。
fn entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, ConversionError> {
    let type_name = EntityTypeName::from_str(entity_type)
        .map_err(|e| ConversionError::InvalidEntity(format!("type `{entity_type}`: {e}")))?;
    let entity_id = EntityId::from_str(id)
        .map_err(|e| ConversionError::InvalidEntity(format!("id `{id}`: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

/// Cedar が `Entities::from_json_value` で受け付ける単一エンティティの JSON 表現
/// `{ "uid", "attrs", "parents" }` を組み立てる。`attrs` に AuthZEN の properties を
/// そのまま載せ、`parents` は空（グループ階層は使わない）。
fn entity_json(entity_type: &str, id: &str, properties: &Map<String, Value>) -> Value {
    json!({
        "uid": { "type": entity_type, "id": id },
        "attrs": properties,
        "parents": [],
    })
}

/// AuthZEN の評価リクエストを、`schema` で検証済みの `(Request, Entities)` ペアに
/// 変換する。
///
/// principal エンティティは常に注入する（ポリシーがその属性を参照できるように）。
/// resource エンティティは属性を持つ場合のみ注入する。静的なエンティティストアを
/// 使わないため、uid 衝突は決して起きない（§4 ②）。
pub fn to_cedar(
    req: &EvaluationRequest,
    schema: &Schema,
) -> Result<(Request, Entities), ConversionError> {
    let principal = entity_uid(&req.subject.entity_type, &req.subject.id)?;
    let action = entity_uid(ACTION_TYPE, &req.action.name)?;
    let resource = entity_uid(&req.resource.entity_type, &req.resource.id)?;

    // AuthZEN の context を Cedar の `Context` に変換する。`Some((schema, &action))`
    // を渡すことで、当該アクションの context スキーマに対して strict 検証され、
    // スキーマ外の属性は弾かれる。context 省略時は空の Context を使う。
    let context = match &req.context {
        Some(value) => Context::from_json_value(value.clone(), Some((schema, &action)))
            .map_err(|e| ConversionError::InvalidContext(e.to_string()))?,
        None => Context::empty(),
    };

    // `Request::new` に `Some(schema)` を渡すと、principal/action/resource の型が
    // スキーマのアクション定義（appliesTo）と整合するかを検証する。未知のアクション
    // や、そのアクションに許可されない principal 型などはここで弾かれる。
    let request = Request::new(
        principal,
        action,
        resource,
        context,
        Some(schema),
    )
    .map_err(|e| ConversionError::InvalidRequest(e.to_string()))?;

    // principal エンティティ（`subject.properties` 由来の属性付き、空の場合もある）を
    // 注入する。resource エンティティは属性を持つ場合のみ追加する。
    let empty = Map::new();
    let subject_props = req.subject.properties.as_ref().unwrap_or(&empty);
    let mut entity_values = vec![entity_json(
        &req.subject.entity_type,
        &req.subject.id,
        subject_props,
    )];
    if let Some(props) = req.resource.properties.as_ref().filter(|p| !p.is_empty()) {
        entity_values.push(entity_json(&req.resource.entity_type, &req.resource.id, props));
    }

    // `Entities::from_json_value` に `Some(schema)` を渡すと、各エンティティの属性が
    // スキーマの shape に一致するか検証される（スキーマ外の属性は弾かれる）。
    // また、スキーマで定義されたアクションエンティティも自動的に補完される。
    let entities = Entities::from_json_value(Value::Array(entity_values), Some(schema))
        .map_err(|e| ConversionError::InvalidProperties(e.to_string()))?;

    Ok((request, entities))
}
