# Keycloak × authzen-sidecar — クライアント別ログイン拒否デモ (AuthZEN)

このデモは、Keycloak に登録された**クライアントごと**に「このユーザーのログインを
拒否すべきか」を判定します。Keycloak のブラウザログインフローにカスタム
**Authenticator (Java SPI)** を差し込み、ユーザー名／パスワード入力の直後に、本リポジトリの
**authzen-sidecar** (PDP) を [AuthZEN](https://openid.github.io/authzen/)
`POST /access/v1/evaluation` API で呼び出し、**属性ベース (ABAC)** の Cedar ポリシーで
ログインの可否を決めます。

```
 Browser ──login──▶ Keycloak ──┐
                               │  AuthZEN /access/v1/evaluation
   (auth-username-password-form)│  subject=user(+attrs) action=login resource=Client
                               ▼
                       authzen-sidecar (PDP) ── Cedar ABAC ポリシー（ファイル）
                               │
        decision=true ─▶ context.success()           ─▶ アプリへリダイレクト（許可）
        decision=false ─▶ context.failure(ACCESS_DENIED) ─▶ "access denied" 画面（拒否）
```

> このデモの PDP は本リポジトリの `authzen-sidecar` です。`cedar-local-agent` を使い、
> **ファイル**（`policies/policies.cedar` + `policies/schema.cedar.json`）からポリシーと
> スキーマを読み込み、リクエストをスキーマ検証した上で評価します。決定契約は
> `decision=true`=Cedar Allow（通常ログイン許可）、`decision=false`=Cedar Deny
> （`forbid` 一致＝外部認証強制）です（[`../../README.md`](../../README.md) / `DESIGN.md` §2.1）。

## 拒否ルール（このデモで実現するもの）

`resource` はログイン先の Keycloak **クライアント**、`subject` はユーザー＋属性です。
次の条件を**すべて**満たすときにログインを**拒否**します。

| クライアント | 拒否条件（すべて満たすとき deny） |
|-------------|----------------------------------|
| **A クライアント** (`a-client`) | 所属 = 社員 (`user_type == "employee"`) ／ 所属部署名が **A 始まり** (`department like "A*"`) ／ アクセス経路 = インターネット (`access_route == "internet"`) |
| **B クライアント** (`b-client`) | 所属 = パートナー (`user_type == "partner"`) ／ アクセス経路 = インターナル (`access_route == "internal"`) |

上記の拒否条件に当てはまらないログインはすべて**許可**されます。

### Cedar での表現（permit + forbid）

ベースで「ログインは許可」し、上記の拒否条件だけを `forbid` で打ち消します。
Cedar では **`forbid` が `permit` を常に上書き**するため、「基本は許可・特定条件のみ拒否」を
そのまま表現できます。実体は本リポジトリの [`../../policies/policies.cedar`](../../policies/policies.cedar)
（スキーマは [`../../policies/schema.cedar.json`](../../policies/schema.cedar.json)）です。

```cedar
// allow-login : ログインは基本すべて許可
permit(principal, action == Action::"login", resource);

// a-client-deny : A クライアントの拒否条件
forbid(principal, action == Action::"login", resource == Client::"a-client")
when { principal has user_type   && principal.user_type == "employee"
    && principal has department  && principal.department like "A*"
    && context   has access_route && context.access_route == "internet" };

// b-client-deny : B クライアントの拒否条件
forbid(principal, action == Action::"login", resource == Client::"b-client")
when { principal has user_type    && principal.user_type == "partner"
    && context   has access_route && context.access_route == "internal" };
```

## デモユーザー（パスワードはすべて `password`）

| User | user_type（所属） | department（所属部署） |
|------|-------------------|------------------------|
| `alice` | employee（社員） | `A-Sales`（A 始まり） |
| `bob` | employee（社員） | `B-Engineering`（A 始まりでない） |
| `carol` | partner（パートナー） | `Partner-Support` |

## コンポーネント

| Service | Port (host) | 役割 |
|---------|-------------|------|
| `keycloak` | http://localhost:8088 | Keycloak 26.1 + AuthZEN authenticator + `authzen-demo` realm のインポート |
| `authzen-sidecar` | http://localhost:9090 | AuthZEN PDP。`../../policies/` をロード（コンテナ内 `/policies`） |
| `app` | http://localhost:9000 | 許可されたときのリダイレクト先（静的ページ） |

> 8088/9090 は Keycloak の 8080 とアプリの 9000 に合わせてずらしています。compose ネットワーク
> 内では Keycloak は常に `http://authzen-sidecar:9000` で PDP に到達します（realm の
> `authzen-config` 参照）。ホストの `9090` は直接 curl で叩くための公開ポートです。

## 起動

```shell
cd demo/keycloak-authzen
docker compose up --build
```

初回は SPI jar（Maven）と authzen-sidecar イメージをビルドし、realm をインポートします。
Keycloak 管理コンソール: http://localhost:8088 (`admin` / `admin`)。

## ブラウザで試す

クライアントの authorize URL を開き、いずれかのユーザーでログインします。

```
http://localhost:8088/realms/authzen-demo/protocol/openid-connect/auth?client_id=CLIENT&redirect_uri=http://localhost:9000/&response_type=code&scope=openid
```

`CLIENT` を `a-client` または `b-client` に置き換えます。

- **許可** → `app` のランディングページにリダイレクト（認可コード付き）。
- **拒否** → Keycloak が "access denied" を表示し、ログインは完了しません。

> **アクセス経路について:** `access_route` はリモート IP から分類します（ループバック /
> RFC1918 ⇒ `internal`、それ以外 ⇒ `internet`）。ローカルからのブラウザアクセスは
> **`internal`** に分類されるため、ブラウザだけで確認できる「拒否」は **B クライアント ×
> carol（パートナー）** です。A クライアントの拒否（= インターネット経由）は、後述の
> PDP への直接 curl、または `X-Forwarded-For` ヘッダで公開 IP を渡して再現します。

### ブラウザでの判定（ローカル = `internal`）

| user \ client | `a-client` | `b-client` |
|---------------|:---:|:---:|
| alice (employee / A-Sales) | ✅ 許可 | ✅ 許可 |
| bob (employee / B-Engineering) | ✅ 許可 | ✅ 許可 |
| carol (partner / Partner-Support) | ✅ 許可 | ❌ **拒否** |

判定の流れはログでも追えます。

```shell
docker compose logs -f keycloak        | grep "AuthZEN"
docker compose logs -f authzen-sidecar | grep "is_authorized"
```

## PDP に直接 curl して全パターンを確認

`access_route` を任意に指定できるので、インターネット経由の拒否も含め全組み合わせを
確認できます（ホストポート `9090`）。

```shell
# A クライアント × alice（社員・A始まり部署）× インターネット → 拒否 (decision:false)
curl -s -X POST http://localhost:9090/access/v1/evaluation \
  -H 'content-type: application/json' -d '{
  "subject":{"type":"User","id":"alice","properties":{"user_type":"employee","department":"A-Sales"}},
  "action":{"name":"login"},
  "resource":{"type":"Client","id":"a-client"},
  "context":{"ip":"203.0.113.10","access_route":"internet"}}'

# B クライアント × carol（パートナー）× インターナル → 拒否 (decision:false)
curl -s -X POST http://localhost:9090/access/v1/evaluation \
  -H 'content-type: application/json' -d '{
  "subject":{"type":"User","id":"carol","properties":{"user_type":"partner","department":"Partner-Support"}},
  "action":{"name":"login"},
  "resource":{"type":"Client","id":"b-client"},
  "context":{"ip":"10.0.0.5","access_route":"internal"}}'
```

### 全判定マトリクス

**A クライアント** (`a-client`) — 拒否条件: 社員 ∧ 部署 `A*` ∧ `internet`

| user | access_route | 判定 |
|------|--------------|:---:|
| alice (employee / A-Sales) | internet | ❌ **拒否** |
| alice (employee / A-Sales) | internal | ✅ 許可 |
| bob (employee / B-Engineering) | internet | ✅ 許可（部署が A 始まりでない） |
| carol (partner / Partner-Support) | internet | ✅ 許可（社員でない） |

**B クライアント** (`b-client`) — 拒否条件: パートナー ∧ `internal`

| user | access_route | 判定 |
|------|--------------|:---:|
| carol (partner / Partner-Support) | internal | ❌ **拒否** |
| carol (partner / Partner-Support) | internet | ✅ 許可 |
| alice (employee / A-Sales) | internal | ✅ 許可（パートナーでない） |

## AuthZEN リクエスト形状

Authenticator はログインごとに次を送信します。

```json
{
  "subject":  { "type": "User", "id": "alice",
                "properties": { "user_type": "employee", "department": "A-Sales" } },
  "action":   { "name": "login" },
  "resource": { "type": "Client", "id": "a-client" },
  "context":  { "ip": "203.0.113.10", "access_route": "internet" }
}
```

`access_route` はリモート IP の分類（`internal` / `internet`）です。Keycloak をリバース
プロキシ配下に置くか、`X-Forwarded-For` ヘッダに公開 IP を入れると `internet` になります。
`context.ip` / `context.access_route` はスキーマ（`schema.cedar.json` の `login` アクション）で
任意属性として宣言されています。

## ポリシーをライブ編集する

`authzen-sidecar` は**ポリシーファイルをポーリング**して再読込します（PUT API はありません）。
マウント元の [`../../policies/policies.cedar`](../../policies/policies.cedar) を編集すると、
`AUTHZ_POLICY_REFRESH_SECS`（このデモでは 15 秒）以内に反映されます。再ビルドは不要です。

```shell
# ../../policies/policies.cedar を編集 → 数秒後に反映。リロードはログで確認できる：
docker compose logs -f authzen-sidecar | grep "policy reloaded"
```

PDP の状態は直接確認できます。

```shell
curl http://localhost:9090/.well-known/authzen-configuration   # PDP ディスカバリ
curl -i http://localhost:9090/healthz                          # liveness
curl -i http://localhost:9090/readyz                           # readiness（リロード健全性）
```

## レイアウト

```
authenticator/   Keycloak Authenticator SPI (Maven, Java 17)
keycloak/        Dockerfile（マルチステージ: jar ビルド → Keycloak イメージ + realm import）
realm/           authzen-demo realm エクスポート（clients / users+属性 / カスタム browser flow）
app/             許可時リダイレクト先の静的ページ
docker-compose.yml
```

> ポリシー／スキーマはこのフォルダには持たず、リポジトリ直下の
> [`../../policies/`](../../policies) を PDP コンテナにマウントして共有します（本番と同じ資産）。

## ログインフローの結線

realm のインポートで、カスタムのトップレベル browser flow `browser-authzen` を定義し、
その `forms` サブフローで `auth-username-password-form` (REQUIRED) → `authzen-access-evaluation`
(REQUIRED) を実行し、realm の browser flow に設定しています。PDP URL / action /
resource type / fail-open は realm 内の `authzen-config` で設定します。

## 注意 / 本番非対応

- PDP 呼び出しは TLS / 認証ヘッダなし。既定で **fail closed**（`failOpen=false`）。
  本番では TLS とタイムアウト調整を行ってください。
- カスタムユーザー属性は realm の **unmanaged attributes** 有効化に依存します
  （インポート realm の user-profile 設定）。
- `access_route` の IP 分類はデモ用ヒューリスティックです。
- 本番の `authzen-sidecar` は Keycloak と同一タスク内で `127.0.0.1` バインドする想定です。
  このデモでは compose ネットワーク越しに到達させるため `AUTHZ_BIND=0.0.0.0:9000` にしています。
