# Deploy: authzen-sidecar on ECS (Keycloak sidecar)

Artifacts:

- [`../Dockerfile`](../Dockerfile) — multi-stage build, distroless runtime.
- [`ecs-task-definition.json`](./ecs-task-definition.json) — Fargate task with
  Keycloak + `authz-sidecar`, S3 Files volume for the policy store.

See [`../DESIGN.md`](../DESIGN.md) §11 / §5 for the design rationale.

## Build & push the image

```bash
# Match the Fargate CPU architecture (linux/amd64 or linux/arm64).
docker buildx build --platform linux/amd64 \
  -t <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/authzen-sidecar:0.1.0 \
  --push .
```

## S3 Files prerequisites (DESIGN.md §5)

- An **S3 file system** linked to a bucket with **S3 Versioning enabled**, holding
  `policies.cedar` and `schema.cedar.json` (see [`../policies/`](../policies)).
- At least one **mount target** in *available* state, in the **same VPC** as the
  task, reachable on **NFS TCP 2049** (security group).
- **Fargate or ECS Managed Instances only** — the EC2 launch type is not supported.

## IAM

- **Task role** (`taskRoleArn`, mandatory for S3 Files): permission to connect to
  the S3 file system and read S3 objects. Scope to the specific file system /
  access point and bucket prefix (least privilege).
- **Execution role**: pull the image from ECR and write CloudWatch logs.

## Volume configuration (key points)

The policy store uses the dedicated `s3filesVolumeConfiguration`:

- `fileSystemArn` (required): `arn:aws:s3files:<REGION>:<ACCOUNT_ID>:file-system/fs-xxxx`
- `accessPointArn` (optional): scope access via an S3 Files access point.
- `rootDirectory` (optional): defaults to `/`.
- Transit encryption is **always on** (cannot be disabled).

Mounted into `authz-sidecar` at `/mnt/s3files` **read-only**.

## How it fits together

- `awsvpc` network → Keycloak reaches the sidecar over `127.0.0.1:9000`.
- Keycloak `dependsOn` the sidecar being `HEALTHY` (container `healthCheck` runs
  `authzen-sidecar health`, which probes `/healthz`).
- A custom Keycloak Authenticator calls `POST /access/v1/evaluation`; a
  `{"decision": false}` means **force external authentication** (DESIGN.md §2.1).

## Replace before applying

`<ACCOUNT_ID>`, `<REGION>`, `fs-xxxxxxxx`, `fsap-xxxxxxxx`, the ECR image URI, and
the Keycloak image/version/config (the Keycloak container here is a minimal
placeholder).
