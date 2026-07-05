# authzen-sidecar

An [OpenID AuthZEN](https://openid.github.io/authzen/) Authorization API server
(Policy Decision Point) backed by [`cedar-local-agent`](https://crates.io/crates/cedar-local-agent).

It runs as a **sidecar to Keycloak** (same ECS task, localhost) and answers,
during Keycloak's authentication flow, whether **external authentication
federation must be forced** for a given user and client — based on per-client
Cedar policies and the user attributes Keycloak sends.

See [`DESIGN.md`](./DESIGN.md) for the full design.

## Decision contract

`POST /access/v1/evaluation` with action `login`:

- `decision: true` — Cedar **Allow** → normal login permitted (external auth **not** forced).
- `decision: false` — Cedar **Deny** (a `forbid` matched) → external auth **forced**.

### Response `context` from policy annotations

`@decision_context_<key>("value")` annotations on the policies that determined the
decision are returned as `context.<key> = "value"` in the response, letting
policies tell the PEP *why* (e.g. `reason_user`) or *what to do next*
(e.g. `step_up`). Other annotations such as `@id` are never exposed; if no
`@decision_context_*` annotation applies, the `context` field is omitted.
See [`DESIGN.md`](./DESIGN.md) §2.2 for the mapping rules.

Writing policies (annotation conventions `@id`/`@description`/`@decision_context_*`,
naming, per-action `decision` meaning, and how to add new use cases) is covered in
[`policies/README.md`](./policies/README.md).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/access/v1/evaluation` | Access evaluation (core) |
| `GET`  | `/.well-known/authzen-configuration` | PDP discovery metadata |
| `GET`  | `/healthz` | Liveness |
| `GET`  | `/readyz` | Readiness (reflects policy reload health) |

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `AUTHZ_BIND` | `127.0.0.1:9000` | Bind address |
| `AUTHZ_POLICY_PATH` | (required) | Cedar policy file (e.g. on the S3 Files mount) |
| `AUTHZ_SCHEMA_PATH` | (required) | Cedar schema JSON |
| `AUTHZ_POLICY_REFRESH_SECS` | `30` | Policy file poll interval (min 15) |
| `AUTHZ_REQUEST_BODY_LIMIT` | `65536` | Max request body bytes |
| `AUTHZ_LOG_FORMAT` | (text) | `json` for JSON logs |

## Run locally

```bash
cargo run -- \
  # env:
  #   AUTHZ_POLICY_PATH=policies/policies.cedar
  #   AUTHZ_SCHEMA_PATH=policies/schema.cedar.json
```

```bash
AUTHZ_POLICY_PATH=policies/policies.cedar \
AUTHZ_SCHEMA_PATH=policies/schema.cedar.json \
cargo run
```

Example request (matches `a-client-deny` → `decision: false` → force external auth):

```bash
curl -s localhost:9000/access/v1/evaluation \
  -H 'content-type: application/json' \
  -d '{
    "subject":  { "type": "User", "id": "u-123",
                  "properties": { "user_type": "employee", "department": "A1" } },
    "action":   { "name": "login" },
    "resource": { "type": "Client", "id": "a-client" },
    "context":  { "access_route": "internet" }
  }'
# => {"decision":false,"context":{"reason_user":"External authentication is required for this access route.","step_up":"external-auth"}}
```

## Health subcommand

For container `healthCheck` in distroless images (no shell/curl):

```
authzen-sidecar health   # exits 0 if /healthz returns 200, else 1
```

<br>
SPDX-License-Identifier: Apache-2.0
