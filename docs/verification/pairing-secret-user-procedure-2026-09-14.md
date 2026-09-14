# Pairing secret prerequisite — prepared user procedure

Status: prepared, not requested or executed. The reviewed deployment manifest and dependent membership/lifecycle implementation are still open. Do not use this document as deployment approval or hosted acceptance evidence.

Target: existing Supabase project `brvzuycnxoswdzzipgvx`. Configuration name: `CONTEXT_RELAY_PAIRING_PEPPER`. The current pairing adapter requires exactly 64 lowercase hexadecimal characters, representing 32 cryptographically random bytes (`supabase/functions/pairing/adapter.mjs`, lines16–18). It uses this server secret to derive HMAC locator digests; no client needs the value.

The prior automated setup was rejected by automatic approval review with only “blocked by policy.” The agent must not retry that setup using another tool, command or browser route. The approved plan permits asking the user to perform the dashboard step after the deployment is concrete. Existing GitHub OAuth settings are complete and are not part of this procedure.

## Ready-to-present user steps

Present these only after final migration/function identities and rollback instructions have been independently reviewed:

1. In regular Chrome, open the existing project's [Edge Function Secrets page](https://supabase.com/dashboard/project/brvzuycnxoswdzzipgvx/functions/secrets). Confirm the project identifier before editing.
2. In your own Windows PowerShell terminal, run the offline command below. It copies 32 cryptographically random bytes encoded as 64 lowercase hexadecimal characters to the clipboard without printing the value. Paste it only into your password manager and the confirmed project's secret field. Do not use an online generator or reuse a password, API key, pairing code or test fixture value. The agent must not run this command or inspect the clipboard.
3. Add the exact name `CONTEXT_RELAY_PAIRING_PEPPER` and paste the generated value into its secret field. Save. Preserve every existing secret.
4. Clear temporary clipboard content, then reply only “pairing secret saved.” Do not send its value, a screenshot containing it, credentials or an exported secret file to the agent.

```powershell
$pairingBytes = New-Object byte[] 32
$pairingRng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $pairingRng.GetBytes($pairingBytes)
    Set-Clipboard -Value ([BitConverter]::ToString($pairingBytes).Replace('-', '').ToLowerInvariant())
} finally {
    [Array]::Clear($pairingBytes, 0, $pairingBytes.Length)
    $pairingRng.Dispose()
}
```

This uses the Windows .NET cryptographic generator's byte-array overload, also available in Windows PowerShell 5.1. [Microsoft RandomNumberGenerator.GetBytes documentation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator.getbytes?view=netframework-4.8.1)

Supabase documents the Dashboard's key/value Save flow and says updated secrets become available immediately; setting the secret does not itself deploy the absent pairing function. [Supabase environment-variable documentation](https://supabase.com/docs/guides/functions/secrets)

The accompanying user-action request must end with this separate explanation: “Automatic approval review rejected automated pairing-secret setup with only ‘blocked by policy.’ That is why this step requires your dashboard action.”

## Verification and evidence

Use the user's dashboard confirmation as the presence checkpoint, recording project ID and confirmation time. Do not issue a general all-secrets listing for this check: its response can include fields beyond the needed name. Do not retrieve, log or display values or digests. The confirmation is not evidence that the format or function behavior is correct; machine verification follows the reviewed deployment through sanitized configuration/behavior checks below.

Deploy only the reviewed migrations before their dependent functions. Record actual deployed migration versions, function versions and source/bundle identities. Check for sanitized configuration failures, then exercise real authenticated invite creation and resolution from the dedicated Windows test profiles. Verify exact membership acceptance, authorization, original session binding, expiry, cancellation, rate limiting and cross-account denial. Missing/invalid Auth rejection alone cannot qualify pairing.

Record terminal results with source/artifact/environment identities in the acceptance ledger. A failure leaves the gate open; do not print the secret to diagnose it.

## Preservation and rollback

Preserve the configured value across ordinary function rollback/redeployment. Changing it changes outstanding invite-code digests and needs a separately reviewed expiration/invalidation procedure. Do not delete accounts, pairing rows, membership history or other secrets to recover from a deployment failure. Schema/function rollback remains governed by the exact reviewed deployment manifest; this prerequisite document does not invent a destructive down migration.
