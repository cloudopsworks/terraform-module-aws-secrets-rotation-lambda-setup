# ADR 0002: OpenAI management-key rotation contract

- **Status:** Accepted
- **Date:** 2026-11-10
- **Scope:** OpenAI admin and project service-account keys rotated by this Lambda. This ADR supersedes ADR 0001's historical OpenAI path; ADR 0001 still governs OpenRouter.

## Context

OpenAI returns a new API key's plaintext only at Create. AWS Secrets Manager versions are immutable, while staging labels move between versions. Terraform owns target secret containers, `TFBOOTSTRAP`, versioned `TFCONFIG`, rotation schedules, and project service-account identities; this Lambda cannot infer a safe key-creation policy from a predecessor credential. A provider Create followed by a failed AWS pending write cannot be made cross-service exactly-once by retrying Create.

## Decision

### Ownership and enrollment

1. One Lambda instance handles only the `openai` provider selected by `settings.type`; the secret payload does not select a provider. `settings.allowed_secrets` scopes the Lambda's IAM access to target Secrets Manager resources, as it does for OpenRouter; it is not copied into a runtime enrollment list. A target must not be the management secret. Every normal step validates secret identity, rotation enrollment, not-deleting state, and the token's `AWSPENDING` or `AWSCURRENT` stage.
2. The management secret is **externally supplied and managed**, by name or ARN at `settings.management_api_key.secret_arn`. Its current JSON is `{"api_key":"<independent admin key>","organization_id":"<org ID>"}`. `settings.openai.organization_id` must match that ID. The Lambda injects the organization binding into OpenAI requests and rejects management plaintext equal to the target key. It never rotates, replaces, or retires the management key. Terraform resolves the management secret's ARN and KMS key through data sources; the Lambda does not manage either resource.
3. Terraform's project and service-account identities are reused, never recreated during key rotation. The Lambda reads service-account and key metadata, checking the account ID, key owner, active access, and configured role when present. It creates admin keys with [POST `/organization/admin_api_keys`](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/admin_api_keys/methods/create) and project keys with [POST `/organization/projects/{project_id}/service_accounts/{service_account_id}/api_keys`](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/service_accounts/subresources/api_keys/methods/create). It captures the one-time plaintext and actual provider ID immediately.

### Secret contracts

4. Every target has a Terraform-owned `TFCONFIG` version with **exactly** these fields and `schema_version: 1`:

   ```json
   {
     "schema_version": 1,
     "key_type": "project",
     "name": "resolved-key-name",
     "project_id": "proj_123",
     "service_account_id": "svc_acct_123",
     "scopes": ["api.model.read"],
     "role": "owner",
     "expires_in_seconds": null
   }
   ```

   `key_type` is `admin` or `project`. Admin requires null `project_id`, `service_account_id`, `scopes`, and `role`; project requires nonempty IDs and allows `role` `owner`, `member`, or null. An explicit expiry is a relative integer TTL of 1–31536000 seconds. The Lambda retries a briefly missing `TFCONFIG` stage, then fails rather than applying defaults. It snapshots its VersionId and complete values for the rotation token; a Terraform replacement does not change an in-flight token.
5. For project keys, `scopes: null` omits the Create field; `scopes: []` sends an empty array. Both mean no key-level restriction requested, **not no access**: [OpenAI says an empty scope array is unrestricted, subject to owner permissions](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys/methods/update). Neither form grants permissions beyond the service account's role.
6. A usable OpenAI credential version contains **exactly** `key_type`, `api_key`, `api_key_id`, `name`, `project_id`, and `service_account_id`. Admin IDs are null. Policy, scopes, expiration, and rotation metadata are not credential fields. A new admin target's exact first-create signal is `{"api_key":null,"api_key_id":"__CREATE_NEW__"}` on one `AWSCURRENT`/`TFBOOTSTRAP` version. A new project target instead has a real provider-created six-field key on its `AWSCURRENT`/`TFBOOTSTRAP` version. The project bootstrap key is retired only after its replacement is tested and promoted. An existing valid six-field active key can rotate without `TFBOOTSTRAP`; malformed sentinels and legacy payloads fail closed.

### Rotation and expiry

7. Implement Secrets Manager's `createSecret`, `setSecret`, `testSecret`, and `finishSecret` using `SecretId` and `ClientRequestToken`. `createSecret` snapshots TFCONFIG, predecessor version/key ID, and lifetime in a separate Lambda-owned `ROTATIONINTENT` version **before** OpenAI Create. It writes the six-field candidate to the token's `AWSPENDING` version. `setSecret` verifies the candidate and pinned intent; there is no OpenAI PATCH to perform. `testSecret` checks provider metadata and candidate authentication. `finishSecret` rechecks stages and predecessor, promotes the candidate to `AWSCURRENT`, then deletes the predecessor using the matching admin or project [delete API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys/methods/delete). It removes only the token's `AWSPENDING` label, leaves `AWSCURRENT` untouched, and removes `ROTATIONINTENT` **last**. It never modifies `TFCONFIG` or `TFBOOTSTRAP`.
8. An explicit `expires_in_seconds` is passed unchanged. When null, the Lambda derives a relative TTL as rotation interval + window allowance + guard, then checks provider metadata for a safely future expiration. Supported derived schedules are `rate(N hours)`, `rate(N days)`, and legacy `AutomaticallyAfterDays`; an unsupported schedule requires an explicit TTL. This avoids silently accepting an unspecified provider default or promoting a nearly expired key.
9. The Lambda authenticates the independent admin credential and candidate admin keys through an admin-key listing. For project candidates, `/models` is attempted only for a configured `owner` role with `scopes` null, empty, or containing `api.model.read`. [OpenAI RBAC](https://developers.openai.com/api/docs/guides/rbac) does not provide one universal read-only probe for arbitrary restricted scopes or roles. For other scope/role combinations, the Lambda uses management-key retrieval to check provider identity and expiry, then records that validation was **metadata-only**, not a candidate-plaintext proof. A 401/403 or other failure from a probe actually attempted is not converted into metadata-only success. Provider metadata is checked in all cases.

### Retries, recovery, and decommissioning

10. Repeated events reuse a matching durable `AWSPENDING` version; they do not create another provider key. The separate intent retains predecessor and configuration-version information until post-promotion retirement and pending cleanup complete. A partial `finishSecret` retry retires that same predecessor. A completed old-token retry cannot remove a newer token's intent.
11. If Create may have succeeded but the pending credential was not durably saved, the intent blocks another Create. The one-time plaintext cannot be recovered. After abandoning the old token's pending stage, an authorized operator calls the custom `reconcileOrphan` step with `SecretId`, old `ClientRequestToken`, `IntentVersionId`, and **exactly one** of a confirmed `OrphanKeyId` or `NoKeyCreatedConfirmed=true`. The Lambda refuses IDs referenced by staged credentials or the predecessor; with a confirmed orphan ID it checks provider metadata and retires that key, and with confirmed noncreation it performs no provider deletion. Name and matching owner are not orphan proof: an incorrect operator-supplied ID can revoke another key with the same metadata. Establish ID provenance from provider/audit evidence before invoking reconciliation; if neither outcome is known, leave the intent in place. It removes only the matching intent; the next rotation needs a new token.
12. Rotation disablement, missing TFCONFIG, or secret deletion scheduling does not imply final-key decommissioning. The Lambda fails safely without revoking the final `AWSCURRENT` provider key. Secrets Manager supplies no deletion callback in the four-step rotation contract; operators must retire the final key separately before deleting the target. Reconciliation remains possible after rotation is disabled but not after secret deletion is scheduled.

## Migration and verification boundary

Complete or reconcile in-flight `AWSPENDING` versions before changing contracts. An existing OpenAI current version lacking any of the exact six credential fields must be migrated outside this Lambda after provider identity is verified; move settings to `TFCONFIG`, and do not guess IDs or scopes from an old payload or Lambda environment. Secret versions cannot be rewritten in place. Serialize rotations and manual staging changes because AWS and OpenAI operations are not atomic.

The explicit `AWSPENDING` cleanup follows the requested secret-label contract, even though [AWS rotation guidance](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html) cautions against a separate removal call. Validate it with a real managed rotation and a subsequent rotation before production use. Local tests do not establish live AWS/OpenAI behavior; a test tag is not a deployment.

## Amendment: IAM-only target scope

The initial implementation also copied `allowed_secrets` into `ENROLLED_SECRET_ARNS_JSON` and required exact ARNs at runtime. This duplicated IAM policy, rejected legitimate IAM wildcard scopes, and made an unrelated KMS ARN in the input fail every OpenAI rotation before provider access. The runtime copy is removed; IAM remains the resource authorization boundary. `MANAGEMENT_SECRET_ARN` remains the one explicit runtime secret-identity exclusion. Exact target ARNs remain the least-privilege recommendation, and KMS ARNs belong in `allowed_kms`, not `allowed_secrets`.

## Amendment: keyless project bootstrap and mandatory expiry

A new project target may replace the real-key bootstrap in decision 6 with the exact six-field project payload, setting `api_key` to null and `api_key_id` to `__CREATE_NEW__` on the same `AWSCURRENT`/`TFBOOTSTRAP` version. Name, project ID, and service-account ID must match `TFCONFIG`. Terraform provisions only the account identity; Lambda creates the first expiring key and records no predecessor key to delete. Later rotations retire only the prior Lambda-issued key. Existing real-key project bootstraps remain accepted for migration.

Every newly issued rotated key requires expiration. Null configured TTL means schedule-derived TTL, not nonexpiry. Provider metadata must confirm a finite timestamp beyond the safety bound before testing or promotion; null, NaN, and infinities fail closed. Offline regression tests cover initial issuance, successor issuance, and missing/nonfinite expiry. This amendment does not migrate existing secret payloads, stage labels, or upstream keys automatically.
