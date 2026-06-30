# ログ仕様（運用向け）

authzen-sidecar（AuthZEN PDP）が出力するログの一覧と、運用での使い方をまとめる。
コードは `src/`、設計は `DESIGN.md` を参照。

---

## 1. ロギング基盤

- **実装**: [`tracing`] + `tracing-subscriber`（`src/main.rs::init_tracing`）。
- **出力先**: 標準出力（stdout）。コンテナログとして収集する想定。
- **フォーマット**:
  - 既定 … 人間可読のテキスト形式。
  - `AUTHZ_LOG_FORMAT=json` … 1 行 1 JSON。**本番ではこちらを推奨**（ログ基盤での
    フィールド検索が容易）。
- **レベル/フィルタ**: 環境変数 `RUST_LOG`（`EnvFilter`）で制御。未設定時は `info`。

ログには大きく 2 系統ある。

| 系統 | target（接頭辞） | 内容 |
|---|---|---|
| アプリログ | `authzen_sidecar`, `authzen_sidecar::handlers` | 本サイドカー自身のログ（本資料の中心） |
| ライブラリ/監査ログ | `cedar_local_agent::*`, `cedar::simple::authorizer` | cedar-local-agent が出すログと OCSF 監査レコード |

> 注: アプリログのメッセージは英語（grep 容易性・ログ基盤との親和性のため）。
> ソースコード中のコメントは日本語。

---

## 2. 推奨設定

```sh
# 本番推奨: アプリログ + OCSF 監査は残し、ライブラリの冗長な INFO は抑制
RUST_LOG="info,cedar_local_agent=warn"
AUTHZ_LOG_FORMAT=json
```

- `cedar_local_agent=warn` … リクエストごとに出る `Received request...` 等の
  定型 INFO を抑止する。**OCSF 監査レコード（target `cedar::simple::authorizer`）は
  残る**ため監査性は損なわれない。
- OCSF レコードも止めたい場合: `RUST_LOG="info,cedar_local_agent=warn,cedar::simple::authorizer=off"`。
- 調査時に詳細を見たい場合: `RUST_LOG=debug`。

---

## 3. アプリログ一覧

`target` 列の `…` は `authzen_sidecar`。フィールドは JSON 形式時のキー。

### 3.1 起動・ライフサイクル

| レベル | target | メッセージ（先頭一致） | 出力タイミング | 運用上の意味 / 対応 |
|---|---|---|---|---|
| INFO | … | `starting authzen-sidecar: bind=… policy=… schema=… refresh=…` | プロセス起動直後 | 解決済みの設定値。**意図した policy/schema パス・bind か確認**。 |
| INFO | … | `loaded and validated policy set: N policies` | 起動時のスキーマ検証成功後 | ロードできたポリシー文の件数。**想定件数と一致するか確認**（マウント取り違え検知）。 |
| INFO | … | `listening on http://ADDR` | 受付開始 | ここまで出れば受付可能。 |
| ERROR | … | `fatal: …`（同文を stderr にも出力） | 起動失敗・致命的エラーで終了する直前 | 設定不正・schema/policy 不正・bind 失敗など。**プロセスは異常終了**。要修正。 |
| (stderr) | — | `failed to start tokio runtime: …` | tracing 初期化前の最初期失敗 | ランタイム起動不可。実行環境の問題。 |
| ERROR | … | `failed to install SIGTERM handler: …` | シグナルハンドラ登録失敗 | グレースフル停止が効かない可能性。まれ。 |
| INFO | … | `shutdown signal received` | SIGTERM/Ctrl-C 受信 | 正常停止の開始。 |

### 3.2 ポリシーのホットリロード

ポリシーファイル（`AUTHZ_POLICY_PATH`）の変更を `AUTHZ_POLICY_REFRESH_SECS` 間隔で
検知して反映する。詳細は `DESIGN.md` §7, §10。

| レベル | target | メッセージ（先頭一致） | 出力タイミング | 運用上の意味 / 対応 |
|---|---|---|---|---|
| INFO | … | `policy reloaded: N policies (EVENT)` | リロード成功 | 新ポリシーが有効化された。件数を確認。`/readyz` は 200 に復帰。 |
| ERROR | … | `policy reload rejected: schema validation failed (…); serving previous policy` | 新ポリシーがスキーマ検証に失敗 | **不正ポリシーは適用されず、直前の正常ポリシーで継続**。`/readyz` が **503**。要ポリシー修正。 |
| ERROR | … | `policy reload failed (serving previous policy): …` | プロバイダの差し替え自体が失敗 | 直前ポリシーで継続。`/readyz` が **503**。I/O 等を確認。 |
| ERROR | … | `policy reload channel closed: …` | 監視タスクが終了 | リロードが今後効かない状態。通常は発生しない。発生時は再起動を検討。 |

### 3.3 アクセス評価（`POST /access/v1/evaluation`）

#### 判定ログ（中核・監査用）

各リクエストにつき 1 行。**ログイン可否の監査の中心**。

| 項目 | 値 |
|---|---|
| レベル | INFO |
| target | `authzen_sidecar::handlers` |
| メッセージ | `access evaluation completed` |

フィールド:

| フィールド | 型 | 説明 |
|---|---|---|
| `subject` | string | 主体。`型::id`（例 `User::alice`）。**属性値(properties)は PII のため出力しない**。 |
| `action` | string | アクション名（例 `login`）。 |
| `resource` | string | リソース。`型::id`（例 `Client::a-client`）。 |
| `decision` | string | `allow` または `deny`。 |
| `external_auth_forced` | bool | `decision=deny` のとき `true`。**外部認証が強制された**ことを示す（AuthZEN 契約、DESIGN.md §2.1）。 |
| `determining_policies` | string | 判定理由となったポリシーの `@id`（カンマ区切り。例 `a-client-deny`）。`@id` 未設定時は Cedar 内部 id（`policy0` 等）。 |
| `latency_ms` | u64 | 評価の所要時間（ミリ秒）。 |

JSON 例:

```json
{"timestamp":"…","level":"INFO","fields":{
  "message":"access evaluation completed",
  "subject":"User::alice","action":"login","resource":"Client::a-client",
  "decision":"deny","external_auth_forced":true,
  "determining_policies":"a-client-deny","latency_ms":0
},"target":"authzen_sidecar::handlers"}
```

#### その他の評価ログ

| レベル | target | メッセージ（先頭一致） | フィールド | 意味 / 対応 |
|---|---|---|---|---|
| WARN | …::handlers | `rejected evaluation request: malformed JSON body: …` | `error_code=invalid_json`, `body_len` | リクエストボディが不正 JSON → **400**。連携元（authenticator 等）の不具合を疑う。 |
| WARN | …::handlers | `rejected evaluation request: schema validation failed: …` | `error_code`, `subject`, `action`, `resource` | スキーマ検証で却下 → **400**。`error_code` は `invalid_entity`/`invalid_context`/`invalid_properties`/`invalid_request`。**スキーマと送信内容の不整合**（例: スキーマ外の属性）。 |
| WARN | …::handlers | `policy evaluation produced errors (offending policies were ignored): …` | `subject`, `action`, `resource` | 評価中に一部ポリシーがエラー（Cedar は当該ポリシーを無視）。**ポリシーの不備**。判定自体は返るが要調査。 |
| ERROR | …::handlers | `authorizer failed: …` | `subject`, `action`, `resource`, `latency_ms` | 認可器自体が失敗 → **500**。プロバイダ I/O 等の異常。 |

### 3.4 レディネス（`GET /readyz`）

| レベル | target | メッセージ | 出力タイミング | 意味 |
|---|---|---|---|---|
| INFO | …::handlers | `readiness probe: not ready (last policy reload failed)` | 未準備（503 を返す）時 | 直近のリロード失敗。3.2 のリロード ERROR と合わせて原因特定。 |

> `GET /healthz`（liveness）と `health` サブコマンド（distroless 用の自己チェック）は
> 正常時はログを出さない。`health` の失敗時のみ stderr に `health: …` を出力する。

---

## 4. ライブラリ / 監査ログ（cedar-local-agent）

`Authorizer::is_authorized` は内部で以下を出す（`target` はモジュールパス
`cedar_local_agent::public::simple`、および OCSF 用の `cedar::simple::authorizer`）。

| レベル | target | 概要 |
|---|---|---|
| INFO | `cedar_local_agent::public::simple` | `Received request, running is_authorized...` ほか定型の進捗ログ（リクエスト毎に複数行）。`request_id`・`authorizer_id` を span フィールドに持つ。 |
| INFO | `cedar::simple::authorizer` | **OCSF（Open Cybersecurity Schema Framework）形式の認可監査レコード**（JSON）。who/what/decision を含む構造化監査ログ。 |
| DEBUG | `cedar_local_agent::public::simple` | `response_diagnostics=…`（判定理由の詳細）。 |

運用方針:

- **監査の正本は OCSF レコード**（`cedar::simple::authorizer`）。長期保管・監査用途はこちら。
- 本サイドカーの**判定ログ（3.3）は運用・トラブルシュート向けの簡潔版**で、AuthZEN の
  識別子・`@id`・レイテンシを 1 行に集約している。両者は併用できる。
- 定型 INFO が冗長な場合は `cedar_local_agent=warn` で抑制（§2）。

---

## 5. 運用レシピ（jq 例）

JSON ログ前提。`LOG` は収集済みログファイルとする。

```sh
# 外部認証が強制されたログインを抽出
jq 'select(.fields.message=="access evaluation completed" and .fields.external_auth_forced==true)' "$LOG"

# 特定ユーザーの判定履歴
jq 'select(.fields.subject=="User::alice")' "$LOG"

# どのポリシーで deny されたかを集計（どのルールが効いているか）
jq -r 'select(.fields.decision=="deny") | .fields.determining_policies' "$LOG" | sort | uniq -c | sort -rn

# 400 になっている連携不具合を抽出（error_code 別件数）
jq -r 'select(.fields.message|startswith("rejected evaluation request")) | .fields.error_code' "$LOG" | sort | uniq -c

# 評価レイテンシの最大値
jq 'select(.fields.message=="access evaluation completed") | .fields.latency_ms' "$LOG" | jq -s 'max'
```

---

## 6. PII（個人情報）の扱い

- **出力する**: 主体/リソースの `型::id`（例: ユーザー名 `User::alice`）。認証監査として必要。
- **出力しない**: `subject.properties`・`resource.properties`（`department` 等）、および
  `context`（`ip` 等）の**属性値**。判定ログには載せない。
  - これらは必要に応じて OCSF レコード側に含まれうるため、OCSF の保管・マスキング方針は
    別途定めること。

---

## 7. 関連

- 設計: `DESIGN.md`（§2 API、§7 リロード、§8 エラー、§10 ヘルス/レディネス）
- 設定: `src/config.rs`（`AUTHZ_*` 環境変数）
- 実装: `src/handlers.rs`（評価/判定ログ）, `src/main.rs`（起動/リロード）

[`tracing`]: https://docs.rs/tracing
