# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting channel for this repository. If
that channel is unavailable, open a minimal public issue asking the repository
owner for a private contact method. Do not include exploit details, live
endpoints, credentials, certificates, private keys, secret plaintext,
Macaroons, discharge tokens, database URLs, or attestation evidence in a public
issue.

Include the affected commit, the operation and trust mode involved, expected
and observed behavior, and a minimal reproduction using synthetic data. Allow
the owner time to investigate before public disclosure.

## Supported code

The current `main` branch is the only supported code line. The repository has
not declared a stable release or compatibility policy.

## Security boundaries

- The broker process, host operating system, configured state directories, and
  operator-supplied master key are trusted. Compromise of those boundaries can
  expose brokered material.
- Every network connection uses mutual TLS. The authenticated principal comes
  from a SPIFFE URI SAN, and request lineage is bound to the live TLS exporter.
- Enforced mode validates ordinary certificate trust, server name, Intel SGX or
  Intel TDX DCAP evidence, PCCS collateral, measured identity, and server
  subject policy. Other quote formats are unsupported and rejected.
- Local mode is only for controlled loopback integration. It preserves mTLS
  but does not provide remote-attestation assurance. The service refuses an
  attestation relaxation on a non-loopback listener.
- V2 secret handles are bearer capabilities. Treat handles, redeem material,
  threshold shares, and discharge tokens as secrets even when caveats narrow
  their authority.
- PostgreSQL credential issuance is active only when its explicit
  administrative configuration is present. The broker does not create that
  trust relationship automatically.

## Operator responsibilities

Keep the master key and TLS private keys outside the repository with restrictive
permissions. Use an approved measured-identity policy and subject allowlist,
protect PCCS connectivity, rotate trust material deliberately, restrict access
to state and transparency logs, and never log or transmit capability material
through an untrusted channel.

This policy describes implementation boundaries; it is not a security
certification or warranty.
