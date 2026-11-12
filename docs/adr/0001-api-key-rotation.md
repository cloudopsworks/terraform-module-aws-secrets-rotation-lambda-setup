# ADR 0001: API-key rotation ownership and secret-version contract

- **Status:** Accepted for OpenRouter; OpenAI path superseded by [ADR 0002](0002-openai-management-key-rotation.md)
- **Date:** 2026-11-10
- **Scope:** Shared API-key ownership and OpenRouter rotation. ADR 0002 owns the current OpenAI contract.

## Context

The module originally rotated database credentials. API-key rotation adds a second lifecycle: a provider creates a plaintext key once, while AWS Secrets Manager assigns immutable version IDs and mutable staging labels. OpenRouter returns the plaintext only from Create, so a retry after an uncertain provider or AWS response cannot assume cross-service exactly-once creation. Earlier OpenRouter iterations derived policy from the old key hash or copied extra fields into the workload secret. The final contract requires resolved creation settings from `TFCONFIG` and a clean credential payload.

## Decisions

### Ownership and configuration

1. The module provisions **one Lambda for one provider**, selected by `settings.type` and passed as `API_PROVIDER`. The secret payload does not select a provider. OpenAI and OpenRouter operations live in separate provider code; the Lambda dispatches to the selected path. Both use the existing standard-library ZIP packaging rather than adding a provider HTTP dependency.
2. The **management API-key secret is pre-existing and externally supplied**. The module never creates, rotates, or stores its plaintext in Terraform. `settings.management_api_key.secret_arn` accepts a secret name or ARN; Terraform resolves the ARN and, when applicable, its KMS key through data sources, then grants the Lambda scoped read/decrypt access and sets `MANAGEMENT_SECRET_ARN` automatically. The rotated workload secret is also external to this module.
3. Provider key IDs are durable secret data: OpenAI stores the returned key ID; OpenRouter stores the returned `hash` as `api_key_id`. AWS `ClientRequestToken` is a *secret VersionId*, not a provider key ID. The Lambda must use `api_key_id` when looking up or retiring a provider key.
4. No Terraform module change is part of the final OpenRouter Lambda-only redesign. Terraform-owned stages `TFCONFIG` and `TFBOOTSTRAP` are never modified by the Lambda.

### OpenAI path — superseded by ADR 0002

5. **Historical, no longer applicable:** OpenAI rotation used the existing workload secret's project, service account, name, and scopes without TFCONFIG. [ADR 0002](0002-openai-management-key-rotation.md) replaces this with versioned TFCONFIG, an organization-bound independent management key, and a six-field credential. Do not use this paragraph to configure new or migrated OpenAI targets.

### OpenRouter secret contract

6. Every OpenRouter rotation reads `VersionStage=TFCONFIG` and requires this exact versioned JSON schema. All fields must exist; nullable fields may be `null`:

   ```json
   {
     "schema_version": 1,
     "name": "resolved-key-name",
     "workspace_id": null,
     "limit": null,
     "limit_reset": null,
     "include_byok_in_limit": null,
     "disabled": null,
     "expires_at": null,
     "creator_user_id": null
   }
   ```

   These are the resolved key-creation settings. A temporarily missing stage is retried; absence or malformed content ultimately **fails closed**, without environment, old-key, or provider defaults. The Lambda snapshots the TFCONFIG VersionId and values per rotation token, so a Terraform replacement during a rotation does not change that token's policy.
7. A new target starts with one `AWSCURRENT`/`TFBOOTSTRAP` version containing `api_key=null` and `api_key_id="__CREATE_NEW__"`. Only that exact value pair with the bootstrap label authorizes first-key creation. Existing active versions with valid credential fields can rotate without `TFBOOTSTRAP`; malformed half-sentinels are rejected.
8. Every **new** OpenRouter `AWSPENDING` and promoted `AWSCURRENT` credential contains only `api_key`, `api_key_id`, `name`, and `workspace_id`. Policy fields (`limit`, `limit_reset`, `include_byok_in_limit`, `creator_user_id`), expiration, and rotation bookkeeping do not belong in the credential. The actual workspace returned by provider management lookup is stored; a non-null configured workspace must match it. A legacy active credential with extra fields may be used as predecessor, but those fields are not copied forward.
9. The Create request sends `name` and each non-null TFCONFIG creation field, preserving `false` and `0`. `disabled` is **update-only** and is PATCHed during `setSecret` when configured, including `false`. An intentionally disabled key is validated through management metadata rather than workload-key authentication.
10. If `TFCONFIG.expires_at` is set, use that future UTC timestamp unchanged. Otherwise derive expiration from the Secrets Manager rotation interval **plus its window allowance and a guarded margin**; do not rely on an unspecified provider default. Supported derived schedules are `rate(N hours)`, `rate(N days)`, or legacy `AutomaticallyAfterDays`; unsupported schedules require an explicit expiration. Pin the derived value in the token snapshot, confirm it through provider metadata, and refuse promotion if a delayed rotation leaves too little safe lifetime.

### Rotation and failure handling

11. Implement Secrets Manager's `createSecret`, `setSecret`, `testSecret`, and `finishSecret` using `SecretId` and `ClientRequestToken`. Validate secret identity, enabled/not-deleting status, and token stages. Create the provider key, capture both plaintext and ID from Create, save the four-field credential as the token's `AWSPENDING` version, then validate it before promotion.
12. Before the non-idempotent provider Create call, write a Lambda-owned `ROTATIONINTENT` version containing the token's pinned configuration/version, predecessor version/key ID, and effective expiry. Keep that stage through set/test, promotion, predecessor retirement, and pending-label cleanup. It is **separate from the credential payload**. A retry reuses an existing matching `AWSPENDING` version; it never issues a second provider key for an unresolved intent.
13. In `finishSecret`, promote the tested version to `AWSCURRENT` first, verify the recorded predecessor and AWS stages, then retire the previous provider key. Remove only the promoted token's `AWSPENDING` label, leave `AWSCURRENT` in place, and remove the matching `ROTATIONINTENT` **last**. After promotion, the stage-addressed `AWSCURRENT` read is retried briefly because Secrets Manager stage reads are eventually consistent; only the promoted token is accepted, and persistent staleness fails closed before retirement so the same token's `finishSecret` retry can complete it. Retries after partial completion use that intent to retire the same predecessor; a completed old-token retry must not touch a newer token's intent. If `finishSecret` stops after promotion and pending-label cleanup but before the intent is removed, the next token's `createSecret` resumes that finish first: it repeats only idempotent predecessor retirement and label cleanup, then proceeds. An intent whose token is not `AWSCURRENT` still blocks a new token. `TFCONFIG` and `TFBOOTSTRAP` remain untouched.
14. If provider Create might have succeeded but the plaintext was not durably saved, stop automatic creation. After abandoning the old token's pending stage, an authorized operator may invoke the explicit `reconcileOrphan` path with the intent ID and either a confirmed orphan hash or confirmation that no key was created. If the plaintext *was* saved but its pending stage was abandoned, the unstaged version records the key hash: reconciliation requires `OrphanKeyId` to equal that stored ID and rejects `NoKeyCreatedConfirmed`. Never identify or delete an orphan by name alone, and never delete an ID referenced by a staged credential (a new rotation's value-less `AWSPENDING` placeholder references none). Reconciliation is not a normal Secrets Manager rotation step.
15. Secret deletion/rotation disablement is **fail-safe, not automatic decommissioning**. Secrets Manager provides no deletion callback in this four-step contract. The Lambda does not infer that a missing TFCONFIG stage, disabled rotation, or deletion scheduling means the final current provider key should be revoked.
16. Lifecycle logs contain identifiers, not plaintext keys or provider response bodies. Exceptions are sanitized at the Lambda boundary. Operators should not enable SDK DEBUG logging where `SecretString` might be exposed.

## Superseded choices and migration

- Looking up policy fields from the old OpenRouter key hash, preserving old secret policy fields, or letting a parameter override the old secret's workspace was superseded by **resolved TFCONFIG as the creation source**. The provider's returned workspace is recorded and checked against a non-null TFCONFIG workspace.
- Embedding `_rotation` metadata in the new credential was superseded by retaining `ROTATIONINTENT` until completion. A secret version is immutable; an already-written five-field in-flight version cannot be rewritten in place. Complete or reconcile such an older rotation before upgrading. New rotations emit four fields only.
- An earlier major-version test tag was withdrawn. Continue the **1.7 pre-release line** for this work; do not turn this Lambda refinement into a major release or rewrite published commit history merely to change a tag.

## Amendment: legacy predecessors are replaced as orphans

OpenRouter target secrets carry `TFCONFIG` only; a `TFBOOTSTRAP` version is optional and used solely for keyless first issuance. A secret whose `AWSCURRENT` predates this module (a non-empty string `api_key`, not the four-field credential shape, not a bootstrap sentinel, not labelled `TFBOOTSTRAP`) previously failed `createSecret` on every retry. Rotation now treats that value as an orphaned predecessor: a schema-2 intent snapshot adds `previous_secret_sha256` and keeps `previous_api_key_id` null, `finishSecret` requires the predecessor to still match that digest, and the legacy key is replaced and kept as `AWSPREVIOUS` but never revoked, because a hash the Lambda never issued is not trusted for deletion. The Lambda logs `adopt_legacy_predecessor_as_orphan` and `predecessor_retirement_deferred` with the retained version ID; operators revoke the key separately. Schema-1 intents remain readable, and a four-field credential that fails validation still fails closed.

## Consequences and verification boundary

The target secret remains externally owned; TFCONFIG replacement and Lambda rotation are coordinated through version snapshots rather than a shared transaction. Retaining an intent prevents unsafe duplicate creation but can require operator reconciliation after an ambiguous failure. Rotations should be serialized: the staging-label protocol is not an atomic cross-token lock. The explicit `AWSPENDING` removal is a chosen cleanup behavior and must be exercised in a real managed rotation before production rollout. Local tests and lint validate the implementation, but they do not prove live AWS/OpenRouter behavior. Any Terragrunt deployment or apply for this module must run under the required `aws-vault exec finconecta` context; no deployment is implied by this ADR or a test tag.
