# AuthZEN ⇄ Cedar マッピング定義一覧

このデモで Keycloak Authenticator が送る **AuthZEN リクエスト**が、`authzen-sidecar` 内で
どのように **Cedar の `principal` / `action` / `resource` / `context`** に変換され、
[`../../policies/policies.cedar`](../../policies/policies.cedar) のポリシーで評価されるかを
まとめる。

変換ロジックの実体は [`../../src/convert.rs`](../../src/convert.rs)（`to_cedar`）、
リクエスト生成元は `authenticator/.../AuthZenAuthenticator.java`（`buildEvaluationRequest`）。

---

## 1. フィールド対応表（AuthZEN → Cedar）

| AuthZEN フィールド | Cedar での表現 | 変換規則 | 取得元（Authenticator） |
|---|---|---|---|
| `subject.type` + `subject.id` | `principal` = `<type>::"<id>"` | `entity_uid(type, id)` で EntityUid 化 | `"User"` 固定 + `user.getUsername()` |
| `subject.properties.*` | `principal` エンティティの属性 | `properties` が principal エンティティの `attrs` として注入される（`principal.<key>` で参照可） | user 属性 `user_type` / `department` |
| `action.name` | `action` = `Action::"<name>"` | エンティティ型は `Action` 固定、id に `name` | authenticatorConfig `action`（default `login`） |
| `action.properties.*` | `action` エンティティ属性 | 受理するが評価には未使用 | — |
| `resource.type` + `resource.id` | `resource` = `<type>::"<id>"` | `entity_uid(type, id)` | authenticatorConfig `resourceType`（default `Client`）+ `clientId` |
| `resource.properties.*` | `resource` エンティティ属性 | properties がある時のみエンティティを注入 | — |
| `context.*` | Cedar `context` レコード | `Context::from_json_value` で**スキーマ検証**の上で投入（`context.<key>` で参照可） | `ip` / `access_route`（remote IP から分類） |

> **ポイント:** `subject.properties` は principal エンティティの属性に変換され、ポリシー内では
> `principal.user_type` のように **エンティティ属性**として参照する。一方 `context` は
> **リクエストの context レコード**になり、`context.access_route` で参照する。同じ「属性」でも
> 参照経路（`principal.X` vs `context.X`）が異なる点に注意。
>
> **スキーマ検証:** `authzen-sidecar` は principal / resource 属性も `context` も
> `schema.cedar.json` で検証する。スキーマに無いエンティティ型・アクション・属性は
> **HTTP 400** で拒否される（このため `login` アクションの context に `access_route` と
> `ip` を任意属性として宣言している）。

---

## 2. 属性の意味（このデモの 3 軸）

| 業務上の意味 | キー | 参照経路 | 取りうる値（例） |
|---|---|---|---|
| 所属 | `user_type` | `principal.user_type` | `employee`（社員） / `partner`（パートナー） |
| 所属部署 | `department` | `principal.department` | `A-Sales` / `B-Engineering` / `Partner-Support` … |
| アクセス経路 | `access_route` | `context.access_route` | `internal`（インターナル） / `internet`（インターネット） |

`access_route` は Authenticator がリモート IP を分類して付与する（ループバック / RFC1918 ⇒
`internal`、それ以外 ⇒ `internet`。`X-Forwarded-For` があればその先頭を採用）。

---

## 3. 具体的なリクエスト → エンティティ変換例

Authenticator が `alice` で `a-client` にインターネット経由でログインしたときの送信ボディ:

```json
{
  "subject":  { "type": "User", "id": "alice",
                "properties": { "user_type": "employee", "department": "A-Sales" } },
  "action":   { "name": "login" },
  "resource": { "type": "Client", "id": "a-client" },
  "context":  { "ip": "203.0.113.10", "access_route": "internet" }
}
```

`authzen-sidecar` 内での評価対象:

| 役割 | Cedar 値 |
|---|---|
| `principal` | `User::"alice"`（属性 `user_type="employee"`, `department="A-Sales"`） |
| `action` | `Action::"login"` |
| `resource` | `Client::"a-client"` |
| `context` | `{ ip: "203.0.113.10", access_route: "internet" }` |

---

## 4. ポリシー定義一覧（`../../policies/policies.cedar`）

「基本は許可（`permit`）・拒否条件のみ `forbid` で打ち消す」構成。Cedar では
**`forbid` が `permit` を常に上書き**するため、`forbid` の `when` を満たすと最終決定は deny。

| ポリシー id | 種別 | 対象 resource | 条件（when） | 参照する属性/コンテキスト |
|---|---|---|---|---|
| `allow-login` | permit | すべて | 条件なし（ログインは基本許可） | — |
| `a-client-deny` | forbid | `Client::"a-client"` | `user_type == "employee"` ∧ `department like "A*"` ∧ `access_route == "internet"` | `subject.properties.user_type` + `subject.properties.department` + `context.access_route` |
| `b-client-deny` | forbid | `Client::"b-client"` | `user_type == "partner"` ∧ `access_route == "internal"` | `subject.properties.user_type` + `context.access_route` |

Cedar 原文（`has` ガードで属性欠落時の評価エラーを回避、部署の前方一致は `like "A*"`）:

```cedar
// allow-login
permit(principal, action == Action::"login", resource);

// a-client-deny
forbid(principal, action == Action::"login", resource == Client::"a-client")
when { principal has user_type   && principal.user_type == "employee"
    && principal has department  && principal.department like "A*"
    && context   has access_route && context.access_route == "internet" };

// b-client-deny
forbid(principal, action == Action::"login", resource == Client::"b-client")
when { principal has user_type    && principal.user_type == "partner"
    && context   has access_route && context.access_route == "internal" };
```

> `forbid` の `when` を満たさない組み合わせは `allow-login` により **許可**。`a-client` /
> `b-client` 以外のクライアントも `allow-login` で許可される。`decision=false`（=Cedar の Deny）を
> 受けた Authenticator は `ACCESS_DENIED` でログインを拒否する。

---

## 5. 判定マトリクス

**A クライアント** (`a-client`) — 拒否条件: 社員 ∧ 部署 `A*` ∧ `internet`

| user | access_route | 決定 | 効いたポリシー |
|---|---|:---:|---|
| `alice` (employee / A-Sales) | internet | ❌ Deny | a-client-deny |
| `alice` (employee / A-Sales) | internal | ✅ Allow | allow-login |
| `bob` (employee / B-Engineering) | internet | ✅ Allow | allow-login（部署が A 始まりでない） |
| `carol` (partner / Partner-Support) | internet | ✅ Allow | allow-login（社員でない） |

**B クライアント** (`b-client`) — 拒否条件: パートナー ∧ `internal`

| user | access_route | 決定 | 効いたポリシー |
|---|---|:---:|---|
| `carol` (partner / Partner-Support) | internal | ❌ Deny | b-client-deny |
| `carol` (partner / Partner-Support) | internet | ✅ Allow | allow-login |
| `alice` (employee / A-Sales) | internal | ✅ Allow | allow-login（パートナーでない） |

各属性の出どころは realm の user 属性（`realm/authzen-demo-realm.json`）。
`access_route` は remote IP の分類で、ローカルからのブラウザアクセスは `internal` になる。

---

## 6. 属性の流れ（end-to-end）

```
Keycloak user 属性                AuthZEN リクエスト              Cedar 評価
─────────────────                ──────────────────             ──────────────
user_type = "employee"   ──▶  subject.properties.user_type   ──▶  principal.user_type
department = "A-Sales"   ──▶  subject.properties.department  ──▶  principal.department
(login 先 clientId)       ──▶  resource.id                    ──▶  resource == Client::"..."
remote IP 分類            ──▶  context.access_route           ──▶  context.access_route
(固定 "login")            ──▶  action.name                    ──▶  action == Action::"login"
```
