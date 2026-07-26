# Security Policy

Report vulnerabilities privately at https://github.com/Skytuhua/Context-Relay/security/advisories/new.

Context Relay is pre-alpha and has no supported stable release. We aim to acknowledge reports within seven days, but this is not an SLA.

## Exposed credentials

Treat every secret-scanning finding as active. Immediately revoke and rotate the credential at its issuer, remove it from the repository and Git history, then require a clean secret scan before closing the incident.
