# ポリシー定義ルール（authzen-sidecar）

この PDP は当初「外部認証連携の強制判定（`login`）」の 1 用途で作られたが、Cedar の
**スキーマ＋ポリシー**を足すだけで、コード変更なしに様々な認可用途へ拡張できる
（DESIGN.md §2.1「アクションは schema で拡張可能」）。実際 `requireMfa`（step-up MFA の
強制）はコード変更なしに追加した 2 つ目の用途で、本書と `policies.cedar`・`schema.cedar.json`
だけで完結している。本書は**ポリシー作者向けの規約**で、複数用途を安全に同居させるための
書き方を定める。

- 実装・アーキテクチャ設計 → [`../DESIGN.md`](../DESIGN.md)
- ライブラリの実挙動（属性欠落時の挙動・schema 検証のタイミング等）→ DESIGN.md §4
- レスポンス `context` のマッピング詳細 → DESIGN.md §2.2

---

## 1. 基本モデル: Cedar の Allow/Deny と AuthZEN の `decision`

- Cedar の評価結果は常に **Allow か Deny** の二値。`permit` が 1 つ以上一致し `forbid` が
  一致しなければ **Allow**、`forbid` が一致するか `permit` が 1 つも一致しなければ **Deny**。
  **`forbid` は常に `permit` に優先**する。
- PDP はこれを機械的に `Allow → decision: true` / `Deny → decision: false` へ変換する
  （`src/handlers.rs`）。**この変換は用途に依らず不変**。
- **重要**: `decision: true/false` が**運用上何を意味するか**は**アクション毎に決まる**。
  PDP は真偽値を返すだけで、その解釈と後続動作は **PEP（呼び出し側）の責務**。
  たとえば `login` では `decision: false`（Deny）は「ログイン拒否」ではなく
  「**外部認証連携を強制**」を意味する（DESIGN.md §2.1）。
  → **新しいアクションを足すときは、必ずその意味を §2 の登録簿に定義する。**

---

## 2. アクション登録簿（`decision` の用途別マッピング）

新しい用途 = 新しい **action**（＋必要なら resource 型・属性）。用途を足すたびに、この表へ
**必ず 1 行追加**し、`decision: true/false` の運用上の意味と PEP の動作を明文化する。
表に無いアクションはリクエスト時に schema 検証で 400 になる（DESIGN.md §8）。

| action | `decision: true`（Allow）の意味 | `decision: false`（Deny）の意味 | PEP（呼び出し側）の動作 | ファミリ |
|---|---|---|---|---|
| `login` | 通常ログインを許可（外部認証を**強制しない**） | 外部認証連携を**強制** | Deny なら外部 IdP リダイレクトへ分岐。Allow なら素通し | 強制系 |
| `requireMfa` | step-up MFA を**要求しない** | step-up MFA を**要求** | Deny なら追加認証（MFA）フローへ分岐。Allow なら素通し。呼ぶべき機構は `context.step_up`（`mfa`）で受け取る | 強制系 |

### 2.1 効果の向きの規約とファミリ

**効果の向きの規約**: 「通常・肯定」の結末を基底の `permit` で表し、「例外・強制・拒否」を
`forbid` で上書きする（`forbid` 常勝を利用）。`login` の `@id("allow-login")` 包括 permit ＋
クライアント別 `forbid`、`requireMfa` の `@id("allow-no-mfa")` 包括 permit ＋ 条件別 `forbid` は
どちらもこの型（DESIGN.md §2.3、`policies.cedar`）。この向きに揃えると `decision: false` =
「何か特別なことが起きる側」で一貫する。

**ただしこの向きは「強制系」ファミリの規約であって、普遍ではない**。この向きが自然に成り立つのは、
`login` / `requireMfa` のように「通常は素通し（Allow）で、リスク条件だけ**追加の強制を発火**（Deny）」
という**強制・step-up 系**の用途に限る。もし将来「リソースにアクセスしてよいか？」のような
**標準アクセス制御系**（`decision: true`＝許可、`false`＝拒否そのもの）を足すなら、向きは逆で
**default-deny ＋ 明示 `permit`** にすべきで、基底 permit の型を流用してはならない（属性欠落時に
Allow へ倒れる＝フェイルオープンになり危険。§4 のフェイル挙動を参照）。

→ **新用途を足すときは、まず「強制系か標準アクセス制御系か」を決める**。強制系なら本節の
基底 permit ＋ forbid 型に揃える。標準アクセス制御系なら default-deny ＋ permit 型にし、
§4 のフェイル挙動が安全側（欠落→Deny）になっていることを確認する。

**`step_up` 値の規約（強制系）**: 強制系の用途が複数あるとき、`@decision_context_step_up` の
**値で機構を区別**する（`login`＝`external-auth`、`requireMfa`＝`mfa`）。PEP は問い合わせた
action ではなく `context.step_up` の値で「次に何を起動するか」を分岐できるため、機構が増えても
PEP 側の分岐が一貫する。

---

## 3. アノテーション規約

Cedar のアノテーション（`@key("value")`）は**評価に影響しない**メタデータ。この PDP が
**解釈するのは 2 種類だけ**で、それ以外はすべて Cedar/PDP に無視される純粋なドキュメントである。
そのため、レビューや運用のためのメタ情報は自由に付けてよい。

| アノテーション | 必須 | 用途 | PEP に返る |
|---|---|---|---|
| `@id("...")` | **必須** | 監査ログの可読 id、`context` マージ順の安定キー | いいえ |
| `@description("...")` | 推奨 | 何を・なぜ（人間・レビュー用の説明） | いいえ |
| `@decision_context_<key>("...")` | 任意 | レスポンス `context.<key>` に載せる（DESIGN.md §2.2） | **はい** |
| `@owner` / `@reference` / `@last_reviewed` 等 | 任意 | 運用メタ（担当・チケット・棚卸し日） | いいえ |

規約:

- **PDP が読むのは `@id` と `@decision_context_*` のみ**。前者は監査ログの可読 id への解決
  （`src/handlers.rs`）、後者はレスポンス `context` への転記（`src/convert.rs`）に使う。
- **レスポンスに漏れるのは `@decision_context_*` だけ**。PII・内部情報・スタックの詳細を
  `decision_context_` に入れてはいけない。人間向けの説明は `@description` に書く。
- アノテーション値は Cedar の制約上**常に文字列**（数値・真偽は文字列で表現）。
- `@decision_context_*` の衝突マージ規則（determining policies のみ・id 文字列順で先勝ち・
  空プレフィックスは無視）は DESIGN.md §2.2。

### 3.1 `@id` の命名規約

- **ケバブケース**、プロジェクト内で**一意**、そして**不変**（ログ・アラート・Runbook が
  この id を参照するため、後から変えると監査が断絶する）。
- 推奨形式: `<用途>-<リソース>-<効果>`。例: `allow-login`（基底許可）、
  `login-a-client-forbid`（a-client の強制）、`b-client-deny`（既存の別表記も可）、
  `allow-no-mfa`（requireMfa の基底許可）、`require-mfa-privileged`（MFA 強制条件）。
- `from_str` が内部で割り当てる `policy0` 等の id はログでは `@id` に解決される。`@id` が
  無いポリシーは内部 id のまま出るため、**必ず付ける**。

### 3.2 `@description` の書き方

1 行目に「**何をするか**」、続けて「**なぜ（背景・リスク・前提）**」を書く。差分レビューで
意図が読み取れることを目安にする。

```cedar
@id("login-a-client-forbid")
@description("a-client: employee かつ 部署 A* かつ インターネット経路のとき外部認証を強制。社外経路からの特権部署アクセスを step-up させるため。")
@decision_context_reason_user("この経路では外部認証が必要です")
@decision_context_step_up("external-auth")
forbid(principal, action == Action::"login", resource == Client::"a-client")
when { ... };
```

---

## 4. ポリシー構造の規約

- **基底 `permit` ＋ 例外 `forbid`**（§2.1 の効果の向き、**強制系の場合**）。`forbid` が常に勝つ。
- **属性ガード**を付ける: `principal has X && principal.X == ...`。属性欠落時は `when` が
  false になり `forbid` 不発 → 基底 permit のまま **Allow**。この**フェイル挙動は用途毎に
  安全側か確認**する。**強制系（`login`/`requireMfa`）は欠落→Allow＝「強制しない」に倒れる
  フェイルオープン**だが、属性付与を Keycloak 側で担保する前提でこれを許容する
  （DESIGN.md §4 ④, §8）。**標準アクセス制御系を足す場合はこの型を流用しない**（§2.1）:
  default-deny ＋ permit にして欠落→Deny（フェイルクローズ）へ倒す。
- **スコープを明示**: `action == Action::"..."`、`resource == <Type>::"..."` で対象を絞る。
  用途（action）とリソースを跨いで誤って一致しないようにする。
- **属性の置き場所**（DESIGN.md §2.1）:
  - principal 側（`subject.properties` 由来）: `user_type`, `department` 等、**ユーザ自身**の属性。
  - context 側: `access_route` 等、**リクエスト環境**の属性。
- `like "A*"` 等のワイルドカード一致が使える。

---

## 5. 新しい用途を追加する手順

1. **ファミリを決める**（§2.1）: 「強制系」（Allow=素通し、Deny=追加の強制）か「標準アクセス制御系」
   （Deny=拒否そのもの）か。以降の効果の向きとフェイル挙動がこれで決まる。
2. **schema を更新**（`schema.cedar.json`）: 必要な entity 型・**action**・属性・context を
   定義する。ここに無い型/action/属性は評価前に弾かれる（ロード時 strict 型検証 →
   DESIGN.md §4 ③', §7、リクエスト時検証 → §8）。
3. **§2 の登録簿に 1 行追加**: その action の `decision: true/false` の運用上の意味・PEP 動作・
   ファミリを明文化する（用途別マッピングの核）。
4. **ポリシーを記述**: `@id`（必須）＋ `@description`（推奨）を付け、ファミリに応じた効果の向き
   （§2.1）に揃える。PEP に伝えたい情報があれば `@decision_context_*` を付ける（強制系で機構が
   複数なら `step_up` の値で区別）。
5. **検証**（§6）。

コード変更は原則不要（action・属性はハードコードせず schema 由来で判定する: DESIGN.md §2.1）。

**worked example（`requireMfa`）**: 上記の手順で実際に追加した 2 つ目の用途。強制系ファミリと
判断し（1）、`schema.cedar.json` に `requireMfa` action を追加（2）、§2 登録簿に 1 行追加（3）、
`policies.cedar` の `allow-no-mfa`（基底許可）＋ `require-mfa-privileged`（条件別 forbid、
`@decision_context_step_up("mfa")` 付き）を記述（4）した。コード変更は 0。

---

## 6. 検証

- **ロード時 schema strict 型検証**: schema に無い型/属性/action を参照するポリシーは、
  起動時は fail-fast、リロード時は反映拒否＋not-ready になる（DESIGN.md §4 ③', §7, §10）。
  「構文は正しいが schema 不整合」なポリシーが live になることはない。
- **ローカル**: `cargo test`（`src/convert.rs` の `context` マッピング等）。Cedar CLI があれば
  `cedar validate --schema schema.cedar.json --policies policies.cedar` でも検証できる。
- **E2E**: デモ設定でサーバを起動し、期待する `decision`/`context` を確認
  （ルート [`../README.md`](../README.md)、ホットリロードは [`../demo/s3-policy-store`](../demo/s3-policy-store)）。

---

## 7. チェックリスト

**Do**

- [ ] ファミリ（強制系／標準アクセス制御系）を決めてから効果の向きを選ぶ（§2.1）
- [ ] `@id` を付ける（ケバブケース・一意・不変）
- [ ] `@description` で「何を・なぜ」を残す
- [ ] 新 action は §2 の登録簿に `decision` の意味・ファミリを追加
- [ ] `principal has X` 等の属性ガードを付け、欠落時のフェイル挙動がファミリの安全側か確認
      （強制系＝欠落で Allow 許容／標準アクセス制御系＝欠落で Deny）
- [ ] 強制系で機構が複数なら `@decision_context_step_up` の値で区別する
- [ ] `action ==` / `resource ==` でスコープを明示

**Don't**

- [ ] `@decision_context_*` に PII・内部情報を入れる（レスポンスに漏れる）
- [ ] 既存 `@id` を変更する（監査ログ・アラートの参照が断絶する）
- [ ] `decision` の意味をアクション毎に定義せず、用途を跨いで直感に頼る
      （`login` の `Deny=強制` のように**用途で意味が反転**しうる）
