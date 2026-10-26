# Security policy

Only the latest alpha is supported on a best-effort basis. There is no production security guarantee or response-time commitment.

Do not include credentials, private source/data or exploit details in public Issues. Use this repository's GitHub **Security → Report a vulnerability** private reporting flow. If that flow is unavailable, contact the maintainer through the GitHub profile to arrange a private channel before sharing details.

Native execution runs with your host permissions and network access; it is not a sandbox. The optional Docker backend constrains its child process, not arbitrary harness tools. Controller receipts/ledgers detect accidental mutation but do not protect against hostile tools running as the same OS user. Inspect code, commands, build contexts and runner definitions before executing unfamiliar projects.

Credential filtering/redaction is best effort. Avoid collecting secrets in the first place. Never mount home directories, credential stores or Docker sockets into untrusted project containers. Explicit authorization and project/harness restrictions remain authoritative.
