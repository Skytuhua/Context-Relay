# Daemon-owned hosted login

Required by the full PR16 release scope. This plan does not enable hosted
services or establish release acceptance.

## Existing boundaries

The renderer has no hosted-auth IPC methods. `SupabaseTransportConfig` requires
an access token and cannot represent signed-out configuration. The existing
`ReqwestHttpClient` enforces HTTPS and rejects redirects. `PlatformKeyStore`
wraps the OS credential store, but its database-key trait has no deletion
operation. Reuse the HTTP client and underlying keyring API; do not use a dummy
access token or widen the database-key interface merely to store a login.

The database has account and device-binding tables, but no first-login
provisioning endpoint. Receiving a Supabase token is therefore insufficient to
activate sync or account deletion.

## Implementation sequence

1. Add a daemon-owned PKCE attempt: OS randomness, S256 challenge, one pending
   attempt, bounded lifetime, cancellation and a loopback listener bound before
   opening the system browser. Keep the verifier and callback code outside the
   renderer. Reject wrong method, host, path, duplicate parameters, oversized
   requests and stale callbacks. An explicit new login invalidates the old one.
2. Exchange the callback through the existing HTTPS client. Bound auth response
   size and redact errors. Store access/refresh credentials only in the OS
   credential store; fail closed if persistence fails. Do not retain the GitHub
   provider token. Validate session identity against the hosted service before
   presenting authenticated state; unverified JWT payloads confer no authority.
3. Serialize refresh with session replacement/logout. Persist rotated tokens
   before publishing the replacement session. A late response cannot restore
   a logged-out or replaced identity. Clear local credentials on logout and
   report whether remote revocation succeeded; do not claim offline logout
   immediately revoked a remote session.
4. Add service-owned first-device provisioning, with live Auth-session checks,
   proof of possession of the installed device key, transactional uniqueness
   and replay protection. Existing accounts require pairing/recovery, not
   automatic creation of a new trusted device from OAuth alone.
5. Persist lifecycle intents in the encrypted vault with the original hosted
   account/session/workspace and action. Then wire authenticated transports,
   preserving the existing ordered worker and explicit recovery/retry behavior.
6. Add desktop-only login/status/cancel/logout IPC and a sign-in surface showing
   only sanitized identity and progress. Complete real GitHub login, restart,
   refresh, logout, account-switch and multi-device acceptance before enabling
   production sync/deletion or marking the release checklist complete.

## Verification

Start with failing checks for callback substitution/replay, expired attempts,
credential-store failure, refresh/logout races and account/session mismatch.
Use the existing injected HTTP seam and disposable Supabase workflow for
deterministic failures. Live provider acceptance must separately verify the
GitHub OAuth AMR claim shape and fresh-auth requirements.

Provider behavior was checked against the official [PKCE guide](https://supabase.com/docs/guides/auth/sessions/pkce-flow)
and [Auth REST specification](https://github.com/supabase/auth/blob/master/openapi.yaml):
the authorization code is single-use and short-lived; token exchange requires
the original verifier. Use Auth's `/token` and `/logout` endpoints, not the
separate OAuth-server APIs. Hosted redirect configuration and signing enrollment
remain pending user input; tests must not create accounts or change providers.

## Desktop control integration

Use `hosted_auth_status`, `hosted_auth_start`, `hosted_auth_cancel` and
`hosted_auth_logout`, restricted to the Desktop IPC role. Start carries a
caller-owned operation ID and expected generation; cancel/logout carry the
generation observed by the desktop. The service must reject stale controls and
make repeated start requests idempotent. State contains a generation and a closed
set of phases/failure reasons, never callback codes, provider details or tokens.
Signed-out state distinguishes remote revocation from local credential deletion.

The daemon owns one active flow and cancels it on replacement/shutdown. Route
these operations outside the ordered vault worker. Reserve control state before
async work, update completion only for the same generation, and open the system
browser from native code only after the listener/attempt is ready. A failed
browser launch must cancel the attempt. Session restoration, explicit retry and
refresh must use the existing owner and enforce expiry in displayed state.

Before committing this integration, advance the local protocol minor to 14,
qualify shutdown-only compatibility with 1.13, independently recompute the HMAC
vectors, regenerate bindings, update strict frontend validation and run protocol,
IPC role/routing and daemon lifecycle checks. The current contract additions alone
do not implement these service behaviors or activate hosted auth.

## Production build configuration

Set `CONTEXT_RELAY_HOSTED_URL` and `CONTEXT_RELAY_HOSTED_PUBLISHABLE_KEY` in
the environment that compiles `contextd`. The daemon embeds both values; runtime
environment changes cannot redirect its credential store or token exchange.
Omitting both produces an offline build with hosted sign-in disabled. Supplying
only one fails the build, as do secret keys, legacy JWT keys and malformed
publishable keys. Use a `sb_publishable_` key, never an administrative key.
Supabase documents publishable keys as suitable for desktop applications in its
[API-key guide](https://supabase.com/docs/guides/getting-started/api-keys).

Production initialization happens after acquiring the daemon instance guard.
HTTP-client and OS credential-store construction run on a blocking worker;
the existing owner then restores and refreshes the saved login. Project URL
validation remains in the shared auth client and credential store. Builds with
invalid hosted configuration fail startup with the existing sanitized diagnostic.
Release automation must supply the verified project configuration before live
acceptance; an offline candidate is not evidence of hosted release readiness.
