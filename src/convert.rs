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
//!
//! 逆方向（Cedar -> AuthZEN）として、判定を決めたポリシーの `@decision_context_<key>`
//! アノテーションをレスポンスの `context` オブジェクトへ変換する
//! [`to_authzen_context`] も提供する（DESIGN.md §2.2）。

use std::str::FromStr;

use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, PolicyId, PolicySet, Request, Schema,
};
use serde_json::{json, Map, Value};
use thiserror::Error;
use tracing::warn;

use crate::authzen::EvaluationRequest;

/// AuthZEN のアクションに用いる Cedar エンティティ型（Cedar ではアクションは
/// 必ず `Action::"<name>"` という固定の型を持つ）。
const ACTION_TYPE: &str = "Action";

/// レスポンス `context` へマッピングするアノテーションキーのプレフィックス。
/// `@decision_context_<key>("value")` が `context.<key> = "value"` になる。
const CONTEXT_ANNOTATION_PREFIX: &str = "decision_context_";

/// AuthZEN リクエストを Cedar 入力へ変換する過程で生じるエラー。
///
/// いずれのバリアントもハンドラで HTTP 400（bad request）にマッピングされる。
#[derive(Debug, Error)]
pub enum ConversionError {
    /// `type`/`id`/`name` を Cedar のエンティティ uid にパースできなかった。
    #[error("invalid entity reference: {0}")]
    Entity(String),
    /// AuthZEN の `context` がスキーマ検証に失敗した。
    #[error("invalid context: {0}")]
    Context(String),
    /// `properties` がエンティティ属性としてのスキーマ検証に失敗した。
    #[error("invalid properties: {0}")]
    Properties(String),
    /// 組み立てたリクエストがスキーマ検証に失敗した（未知のアクション・型など）。
    #[error("invalid request: {0}")]
    Request(String),
}

impl ConversionError {
    /// JSON エラーボディ用の安定したエラーコード（DESIGN.md §8）。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Entity(_) => "invalid_entity",
            Self::Context(_) => "invalid_context",
            Self::Properties(_) => "invalid_properties",
            Self::Request(_) => "invalid_request",
        }
    }
}

/// `type` + `id` のペアから Cedar のエンティティ uid を組み立てる（値はそのまま使う）。
fn entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, ConversionError> {
    let type_name = EntityTypeName::from_str(entity_type)
        .map_err(|e| ConversionError::Entity(format!("type `{entity_type}`: {e}")))?;
    let entity_id =
        EntityId::from_str(id).map_err(|e| ConversionError::Entity(format!("id `{id}`: {e}")))?;
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
            .map_err(|e| ConversionError::Context(e.to_string()))?,
        None => Context::empty(),
    };

    // `Request::new` に `Some(schema)` を渡すと、principal/action/resource の型が
    // スキーマのアクション定義（appliesTo）と整合するかを検証する。未知のアクション
    // や、そのアクションに許可されない principal 型などはここで弾かれる。
    let request = Request::new(principal, action, resource, context, Some(schema))
        .map_err(|e| ConversionError::Request(e.to_string()))?;

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
        entity_values.push(entity_json(
            &req.resource.entity_type,
            &req.resource.id,
            props,
        ));
    }

    // `Entities::from_json_value` に `Some(schema)` を渡すと、各エンティティの属性が
    // スキーマの shape に一致するか検証される（スキーマ外の属性は弾かれる）。
    // また、スキーマで定義されたアクションエンティティも自動的に補完される。
    let entities = Entities::from_json_value(Value::Array(entity_values), Some(schema))
        .map_err(|e| ConversionError::Properties(e.to_string()))?;

    Ok((request, entities))
}

/// 判定を決めたポリシー（`reason_ids`）の `@decision_context_<key>` アノテーションを
/// AuthZEN レスポンスの `context` オブジェクトへマッピングする（DESIGN.md §2.2）。
///
/// - 対象は `decision_context_` で始まるキーのみ。`@id` などその他のアノテーションは
///   レスポンスに漏らさない。
/// - `reason()` の列挙順は非決定的なため、ポリシー id の文字列順に走査して
///   結果を決定的にする。同一キーの衝突は先勝ちとし、ポリシー不備の検知の
///   ため warn ログに残す。
/// - 該当アノテーションが 1 つもなければ `None`（`context` フィールド省略）。
pub fn to_authzen_context(
    policy_set: &PolicySet,
    reason_ids: &[&PolicyId],
) -> Option<Map<String, Value>> {
    let mut ids = reason_ids.to_vec();
    ids.sort_unstable_by_key(|id| id.to_string());

    let mut context = Map::new();
    for id in ids {
        let Some(policy) = policy_set.policy(id) else {
            continue;
        };
        for (key, value) in policy.annotations() {
            let Some(context_key) = key.strip_prefix(CONTEXT_ANNOTATION_PREFIX) else {
                continue;
            };
            if context_key.is_empty() {
                warn!(
                    policy_id = %id,
                    "ignoring `@decision_context_` annotation without a context key"
                );
                continue;
            }
            match context.entry(context_key.to_string()) {
                serde_json::map::Entry::Vacant(entry) => {
                    entry.insert(Value::String(value.to_string()));
                }
                serde_json::map::Entry::Occupied(_) => {
                    warn!(
                        policy_id = %id,
                        context_key,
                        "conflicting `@decision_context_` annotation across determining policies; \
                         keeping the value from the lexicographically first policy id"
                    );
                }
            }
        }
    }

    (!context.is_empty()).then_some(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用ポリシー集合をソーステキストから組み立てる。
    fn policy_set(src: &str) -> PolicySet {
        PolicySet::from_str(src).expect("test policy set should parse")
    }

    /// `@id` アノテーションの値からポリシー id を引く（`from_str` が割り当てる
    /// `policy0` 等の内部 id に依存しないため）。
    fn find_id<'a>(ps: &'a PolicySet, name: &str) -> &'a PolicyId {
        ps.policies()
            .find(|p| p.annotation("id") == Some(name))
            .map(|p| p.id())
            .unwrap_or_else(|| panic!("policy `{name}` not found"))
    }

    #[test]
    fn maps_prefixed_annotations_to_context() {
        let ps = policy_set(
            r#"
            @id("deny-admins")
            @decision_context_reason_user("additional authentication required")
            @decision_context_step_up("mfa")
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "deny-admins")];

        let context = to_authzen_context(&ps, &reason).expect("context should be present");
        assert_eq!(
            context.get("reason_user"),
            Some(&Value::String("additional authentication required".into()))
        );
        assert_eq!(context.get("step_up"), Some(&Value::String("mfa".into())));
        assert_eq!(context.len(), 2, "`@id` must not leak into the context");
    }

    #[test]
    fn returns_none_without_matching_annotations() {
        let ps = policy_set(
            r#"
            @id("allow-all")
            permit(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "allow-all")];

        // `@id` しか付いていないポリシー、および reason が空のケースは共に None。
        assert_eq!(to_authzen_context(&ps, &reason), None);
        assert_eq!(to_authzen_context(&ps, &[]), None);
    }

    #[test]
    fn first_policy_in_id_order_wins_on_conflict() {
        let ps = policy_set(
            r#"
            @id("first")
            @decision_context_reason_user("from first")
            forbid(principal, action, resource);

            @id("second")
            @decision_context_reason_user("from second")
            @decision_context_extra("kept")
            forbid(principal, action, resource);
            "#,
        );
        // `from_str` は定義順に policy0, policy1 を割り当てるため、id の文字列順 =
        // 定義順になる。逆順で渡してもソートにより "first" の値が勝つこと。
        let reason = [find_id(&ps, "second"), find_id(&ps, "first")];

        let context = to_authzen_context(&ps, &reason).expect("context should be present");
        assert_eq!(
            context.get("reason_user"),
            Some(&Value::String("from first".into()))
        );
        // 衝突しないキーは全ポリシーからマージされる。
        assert_eq!(context.get("extra"), Some(&Value::String("kept".into())));
    }

    #[test]
    fn valueless_annotation_maps_to_empty_string() {
        let ps = policy_set(
            r#"
            @id("flag-only")
            @decision_context_flag
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "flag-only")];

        let context = to_authzen_context(&ps, &reason).expect("context should be present");
        assert_eq!(context.get("flag"), Some(&Value::String(String::new())));
    }

    #[test]
    fn skips_prefix_only_annotation() {
        let ps = policy_set(
            r#"
            @id("broken")
            @decision_context_("no key")
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "broken")];

        assert_eq!(to_authzen_context(&ps, &reason), None);
    }
}
