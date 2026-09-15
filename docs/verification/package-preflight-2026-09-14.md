# GitHub and package implementation preflight

Read-only source inspection on September 14, 2026, at local HEAD `3c10e5e`
with the separate Task4 membership changes uncommitted. This is a requirements
and reuse map, not implementation, execution, or release acceptance evidence.
T18, T19 and RB-PACKAGE remain open. Apple and paid work remain deferred.

## Binding scope

The [original implementation plan](../context-relay-v1-implementation-plan.md)
defines GitHub integrations, Tasks18–19 and the Packages and setup matrix.
GitHub OAuth login and repository access through a separate GitHub App are
different capabilities. The App requires only Metadata read and Contents read,
selected public/private repositories, account/device validation before issuing
short-lived tokens, memory-only token handling, direct GitHub archive download,
and denial after disconnect or for an unselected repository.

Package acceptance requires immutable commit resolution, bounded quarantine,
complete dependency closure, exact-byte Gitleaks/Semgrep scanning, adapter plans,
passive changes, explicit active-change approval, disabled installation,
installed-byte verification and native validation before enablement. Any byte
or plan change invalidates approval. Mutable-refetch CLIs remain manual-only.
Removal must preserve user data, credentials and unrelated dependencies.

The full matrix additionally includes traversal, normalized-path collisions,
links, device files, ADS, bombs, oversized/nested packages, secret canaries,
obfuscated hooks, binary payloads, missing licenses, scanner failures, expired
approval, rejected batches, CLI partial failures and running harness refusal.
These requirements cannot be replaced with manifest serialization tests.

## Existing code to reuse and inspect before extending

| Source | Verified role and limit |
| --- | --- |
| [Package protocol](../../crates/protocol/src/packages.rs) and [schema](../../schemas/context-relay-package-v1.json) | Manifest/component/immutable-dependency data and validation exist. Their presence does not establish download, inspection or installation. |
| [Package bounds tests](../../crates/protocol/tests/package_bounds_v1.rs), [serialization tests](../../crates/protocol/tests/package_serialization_allocations_v1.rs), [format tests](../../crates/protocol/tests/packages_v1.rs) | Existing protocol coverage to retain; not rerun during this preflight. |
| [Native transaction exports](../../crates/core/src/native_transaction/mod.rs), [model](../../crates/core/src/native_transaction/model.rs), [approval](../../crates/core/src/native_transaction/approval.rs) | Existing sealed plans, approval hashes, approved inputs/CLI declarations, ownership and receipts provide reuse candidates. Package-specific complete-closure binding and execution coverage still need verification. |
| [Native runner](../../crates/native-runner/src/lib.rs) | Existing runner boundary is a reuse candidate; prior native isolation results do not prove package archive safety or exact scanned-to-installed bytes. |

A scoped graph query followed by filename and symbol searches in core, daemon,
desktop and Edge Functions did not find a production GitHub App client or
package quarantine/install module. Matches included protocol DTOs and tests,
generated desktop types, unrelated local-IPC installation tokens and sync
quarantine. This supports retaining the audit's missing status, not an
exhaustive proof about every repository file. Graph query results were truncated;
the graph is navigation evidence only.

## Database contract to reconcile

The published [initial hosted migration](../../supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql)
creates `public.github_installations` with required JSONB
`encrypted_token_reference`. The current plan permits only installation IDs,
repository IDs and metadata to persist; GitHub access tokens stay in daemon
memory. The field name is not evidence that any token is stored: no user rows
were read. Before implementing T18, define the metadata representation and
reconcile this required column through an additive migration if necessary.
Do not store encrypted access tokens merely to satisfy the old column, or edit
the published migration in place.

The separate [live permission snapshot](hosted-permissions-2026-09-14.md)
observed RLS and no anonymous/authenticated table CRUD privileges for this table.
That does not verify future token issuance, selected-repository authorization,
disconnect behavior, GitHub consent permissions or token lifetime.

## Next implementation boundary

Finish and independently review membership material activation/reconstruction,
then integrate the real hosted device lifecycle. The GitHub/package work must
use the resulting account/device authorization and existing native transaction
facilities. Before implementation, trace those full flows and preserve the
complete T18/T19/RB-PACKAGE acceptance matrix. No new dependency, provider
configuration, permission grant, token issuance or package execution occurred
in this preflight.
