# Repository Settings Checklist

Task 3 must apply and verify available settings after CI exists and GitHub authentication is restored.

- Enable GitHub secret scanning and provider-pattern push protection.
- Until organization-only non-provider patterns and validity checks are
  licensed, require the `Secret Scan` status check. It scans every Git ref with
  the hash-pinned Gitleaks release and permits only the reviewed synthetic test
  fixture fingerprints.
- Treat every finding as active and revoke and rotate it at the issuer.
- Enable Dependabot alerts and security updates.
- Enable private vulnerability reporting.
- Set the GitHub Actions token to read-only.
- Require squash-only merges.
- After CI exists, configure rulesets for `main` and `v*`.
