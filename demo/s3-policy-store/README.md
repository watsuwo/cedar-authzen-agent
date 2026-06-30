# ローカル S3 ポリシーストア デモ

ポリシーストアとして **S3 を使う本番構成（DESIGN.md §5）を、ローカルで再現**する
デモ。FUSE もクラウドも不要で、`docker compose` だけで動く。

「MinIO（ローカル S3）にポリシーを置く → ファイルへ射影 → PDP がホットリロード」
という**本番と同じ更新フロー**を実際に体験できる。

---

## なぜこの構成か

本番（DESIGN.md §5）:

```
管理者 --PutObject--> S3 バケット --(S3 Event)--> S3 Files が常駐ファイルを更新
                                                          │ read（普通のファイル）
                                                          ▼
                                            authzen-sidecar (PDP)
                                            file_inspector_task が変更検知 → reload
```

PDP は **ストレージ非依存**で、ただのファイルパス（`AUTHZ_POLICY_PATH`）を読むだけ。
「S3 が真実の source、それを常駐ファイルへ射影する何かがいて、PDP はそのファイルを
監視する」というのが本質。これを **FUSE 権限なし**でローカル再現する:

| 本番 | このデモでの代役 | 役割 |
|---|---|---|
| Amazon S3 バケット | **minio** | ポリシーの真実の source（オブジェクトストア） |
| S3 Files（NFS マウント） | **policy-projector**（`mc mirror --watch`） | S3 → 常駐ファイルへの射影 |
| S3 Event 反映 + ポーリング | `--watch` + `AUTHZ_POLICY_REFRESH_SECS` | 更新の伝播 |
| 常駐ファイル `/mnt/s3files/...` | 共有ボリューム `policy-store:/policystore` | PDP が read するファイル |
| authzen-sidecar | **authzen-sidecar**（同一バイナリ・同一 env） | PDP 本体（差分なし） |

PDP のコード・設定は本番と同じ。**違うのは「読むファイルが S3 射影先である」ことだけ**。

---

## 構成

```
services:
  minio            … ローカル S3 互換ストア（コンソール :9001 / S3 API :9101）
  minio-setup      … 一度だけ: バケット作成 + Versioning 有効化 + 初期ポリシー投入
  policy-projector … mc mirror --watch でバケット→/policystore へ射影し続ける
  authzen-sidecar  … /policystore のファイルを読む PDP（:9090 で公開）
```

初期ポリシー/スキーマはリポジトリの `../../policies/` を投入する。

---

## 前提

- Docker / `docker compose`
- ホストのポート `9090`（PDP）, `9001`（MinIO コンソール）, `9101`（S3 API）が空いていること

---

## 起動

```sh
cd demo/s3-policy-store
docker compose up -d --build
```

初回は PDP イメージ（Rust）のビルドに数分。`policy-projector` が healthy に
なってから PDP が起動する（初期ミラー完了を待つため）。

状態確認:

```sh
docker compose ps
# authzen-sidecar / policy-projector が healthy になっていれば OK
```

---

## 動作確認（評価）

`a-client` は「従業員 × 部署 A* × インターネット経由」のとき外部認証が強制される
（`decision:false`）。

```sh
# DENY（外部認証強制）になるケース
curl -s localhost:9090/access/v1/evaluation \
  -H 'content-type: application/json' \
  -d '{"subject":{"type":"User","id":"alice","properties":{"user_type":"employee","department":"Apex"}},
       "action":{"name":"login"},
       "resource":{"type":"Client","id":"a-client"},
       "context":{"access_route":"internet"}}'
# => {"decision":false}
```

---

## ホットリロードの実演（S3 更新 → 自動反映）

### 方法 A: CLI（`mc`）でオブジェクトを差し替え

`policy-projector` コンテナに `mc`（alias `local`）が入っているので、そこから put する。

```sh
# 例: forbid を外して「全部 allow」のポリシーに差し替える
docker compose exec -T policy-projector sh -c \
  'printf "@id(\"allow-login\")\npermit(principal, action == Action::\"login\", resource);\n" \
   | mc pipe local/authzen-policies/policies.cedar'
```

### 方法 B: Web コンソールからアップロード

1. http://localhost:9001 を開く（ユーザー `minioadmin` / パスワード `minioadmin`）
2. バケット `authzen-policies` を開く
3. `policies.cedar` を新しい内容でアップロード（上書き）

### 反映の確認

`AUTHZ_POLICY_REFRESH_SECS=15` なので、最大 ~15 秒で反映される。

```sh
# さっきと同じ DENY ケースが、allow-only ポリシーでは ALLOW に変わる
curl -s localhost:9090/access/v1/evaluation -H 'content-type: application/json' \
  -d '{"subject":{"type":"User","id":"alice","properties":{"user_type":"employee","department":"Apex"}},
       "action":{"name":"login"},"resource":{"type":"Client","id":"a-client"},
       "context":{"access_route":"internet"}}'
# => {"decision":true}  ← ホットリロードされた

# PDP のリロードログ
docker compose logs authzen-sidecar | grep -i reload
```

> **不正なポリシーを put した場合**: PDP はスキーマ検証で却下し、**直前の正常な
> ポリシーで提供を継続**する（`/readyz` が 503 になる）。DESIGN.md §10。

---

## S3 Versioning（本番要件のローカル再現）

本番では S3 Files の要件としてバケットの **Versioning が必須**（DESIGN.md §5.1）。
このデモでも `minio-setup` が有効化しているので、更新履歴を確認できる。

```sh
docker compose exec -T policy-projector sh -c \
  'mc ls --versions local/authzen-policies/policies.cedar'
```

---

## クリーンアップ

```sh
docker compose down -v   # コンテナ + ボリューム（MinIO データ・射影先）を削除
```

---

## Keycloak デモと組み合わせる場合

`demo/keycloak-authzen/` は現在 `../../policies` を直接バインドマウントしている。
そちらの PDP をこの「S3 射影先」に向けたい場合は、keycloak 側 compose の
`authzen-sidecar` の `volumes` を `policy-store:/policystore:ro` に、`AUTHZ_*_PATH` を
`/policystore/...` に変更し、本デモの `minio` / `minio-setup` / `policy-projector` を
同じ compose（または外部ネットワーク共有）に取り込めばよい。
