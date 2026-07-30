# authzen-pdp

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

## Response `context`

The `context` object carries two kinds of fields; it is omitted entirely when
none of them apply.

| Key | Type | Source |
|---|---|---|
| `reason` | string array | PDP-reserved: `@id` of every determining policy, sorted (internal id such as `policy0` when a policy has no `@id`) |
| `errors` | string array | PDP-reserved: Cedar evaluation errors, present only when a policy errored (those policies are ignored in the decision) |
| `<key>` | string | `@decision_context_<key>("value")` on the policy that supplied the context |

`reason` and `errors` are reserved: if a policy defines
`@decision_context_reason` / `@decision_context_errors`, the PDP value wins and
a warning is logged.

### Annotation-derived keys

`@decision_context_<key>("value")` annotations on the policy that determined the
decision are returned as `context.<key> = "value"`, letting policies tell the
PEP *why* (e.g. `reason_user`) or *what to do next* (e.g. `step_up`). Other
annotations such as `@id` are never exposed.

When several policies determine the decision, **exactly one supplies all of the
annotation-derived keys** — the one with the lowest
`@priority("<non-negative integer>")` (unset = lowest priority, ties broken by
`@id` order). Keys are never merged across policies, so a reason and its
follow-up action always come from the same policy. `@priority` affects only this
selection, never the Allow/Deny decision. See [`DESIGN.md`](./DESIGN.md) §2.2
for the full mapping rules.

Writing policies (annotation conventions `@id`/`@priority`/`@description`/`@decision_context_*`,
naming, per-action `decision` meaning, and how to add new use cases) is covered in
[`policies/README.md`](./policies/README.md).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/access/v1/evaluation` | Access evaluation (core) |
| `GET`  | `/.well-known/authzen-configuration` | PDP discovery metadata |
| `GET`  | `/healthz` | Liveness |
| `GET`  | `/readyz` | Readiness (reflects policy reload health) |

Evaluation errors return `{"error": "<code>", "message": "..."}`:
`400` with `invalid_json` / `invalid_request` / `invalid_entity` /
`invalid_context` / `invalid_properties` (malformed body or a request the Cedar
schema rejects), `500` with `evaluation_failed`.

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `AUTHZ_BIND` | `127.0.0.1:9000` | Bind address |
| `AUTHZ_POLICY_PATH` | (required) | Cedar policy file (e.g. on the S3 Files mount) |
| `AUTHZ_SCHEMA_PATH` | (required) | Cedar schema JSON |
| `AUTHZ_POLICY_REFRESH_SECS` | `30` | Policy file poll interval (15s or longer recommended) |
| `AUTHZ_LOG_FORMAT` | (text) | `json` for JSON logs |
| `RUST_LOG` | `info` | Log level / filter (`tracing` `EnvFilter` syntax) |

Policies and schema are validated at startup (fail-fast) and on every reload;
a rejected reload keeps the previous policy set and flips `/readyz` to `503`.

## Run locally

```bash
AUTHZ_POLICY_PATH=policies/policies.cedar \
AUTHZ_SCHEMA_PATH=policies/schema.json \
cargo run
```

Example request
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
# => {"decision":false,"context":{"reason":["a-client-deny"],"reason_user":"External authentication is required for this access route.","step_up":"external-auth"}}
```

Tests: `cargo test`.


## Health subcommand

For container `healthCheck` in distroless images (no shell/curl):

```
authzen-pdp health   # exits 0 if /healthz returns 200, else 1
```