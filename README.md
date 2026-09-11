# Secret Broker

Secret Broker is a Rust workspace for issuing, storing, and recovering secrets through authenticated gRPC calls. It contains:

- `secret-broker-client`: a typed client whose only public connection path requires explicit mTLS identity, trust roots, server name, and an attestation mode.
- `secret-broker`: the standalone broker service and the `secretbroker.v1` protocol.

Copyright is held by the repository owner. All rights are reserved; no software
license is granted until the owner explicitly selects one.

## What the broker does

The protocol exposes these groups of operations:

- wrap, unwrap, delete, renew, revoke, and rotate secret capabilities;
- mint AEAD-key capabilities, with optional threshold shares and custodian claims;
- attenuate a capability with first-party or third-party caveats, then mint a discharge for the opaque caveat identifier returned by attenuation;
- encrypt/decrypt, sign/verify, generate random bytes, generate post-quantum key pairs, and retrieve their public keys;
- optionally issue temporary PostgreSQL credentials when the broker is configured with an administrative PostgreSQL connection.

Secrets use the `secretbroker.v1` gRPC package. The `.v1` suffix versions the wire
namespace; it is not the capability-handle version. Every externally usable
secret handle is a signed, serialized Macaroon prefixed with `broker:v2:`. The
service rejects bare UUIDs, `broker:v1:` handles, and unsigned
`broker:v2:<uuid>` values before looking up sealed state. The complete wire
contract is in [`proto/secret_broker.proto`](proto/secret_broker.proto).

## Build and verify

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
```

The workspace requires Rust 1.82 or newer.

## Trust model

The public client has exactly two modes:

| Mode | Use | Requirements |
| --- | --- | --- |
| `enforced` (default) | Any non-loopback endpoint | HTTPS; client certificate, key, CA bundle, and server name; a non-empty measured-identity policy; a non-empty server-subject allowlist; and `SECRET_BROKER_PCCS_URL`. The client verifies the ordinary TLS chain before RA-TLS evidence, PCCS collateral, measurements, and subject policy. |
| `local` | Controlled loopback integration only | HTTPS plus mTLS. The client rejects `local` for non-loopback endpoints and does not accept an attestation policy, subject list, or PCCS URL in this mode. |

There is no public disabled, stub, SPIFFE-only, permissive-verifier, or allow-all client mode. A client connection is established eagerly, the generated gRPC module and protocol adapter are private, and consumers cannot construct the underlying transport directly.

The enforced RA-TLS verifier accepts Intel SGX and Intel TDX DCAP quote formats that it can validate with PCCS collateral. An unrecognized quote header is rejected as unsupported; the code does not infer a vendor it cannot verify.

The standalone broker requires a client certificate and derives the authenticated principal from a SPIFFE URI SAN. It derives TLS-exporter context from the live mTLS connection. Peer attestation and discharge-attestation checks default to enabled. A controlled local integration test may set `SECRET_BROKER_REQUIRE_ATTESTATION=false` and `BROKER_REQUIRE_DISCHARGE_ATTESTATION=false` while exercising loopback mTLS without RA-TLS evidence. Startup rejects either relaxation on a non-loopback bind; local mTLS is not an attestation substitute.

## Broker configuration

The standalone binary is `secret-broker`.

Required broker variables:

| Variable | Meaning |
| --- | --- |
| `BROKER_MASTER_KEY_FILE` | Path to an existing **32-byte** master-key file. The service enforces mode `0600` on Unix. |
| `SECRET_BROKER_TLS_CERT` | PEM server certificate chain. |
| `SECRET_BROKER_TLS_KEY` | PEM server private key. |
| `SECRET_BROKER_TLS_CA_CERT` | PEM CA bundle used to authenticate client certificates. |

Common explicit state variables:

| Variable | Meaning |
| --- | --- |
| `SECRET_BROKER_BIND_ADDR` | Listener address; defaults to `127.0.0.1:50052`. |
| `BROKER_SLED_PATH` | Sealed-record store path. |
| `BROKER_TRANSPARENCY_LOG` | Transparency-log path. |
| `CRYPTO_ENGINE_SEALED_STORE_PATH` | Post-quantum crypto-state path. |
| `CRYPTO_ENGINE_HSM_TYPE` | This build accepts only `software`; another value is rejected. |
| `SECRET_BROKER_PCCS_URL` | The sole PCCS configuration name used for RA-TLS verification. |
| `SECRET_BROKER_REQUIRE_ATTESTATION` | Require peer RA-TLS evidence; defaults to `true`, and may be `false` only on a loopback bind. |
| `BROKER_REQUIRE_DISCHARGE_ATTESTATION` | Require attested discharge minting; defaults to `true`, and may be `false` only on a loopback bind. |
| `BROKER_DISCHARGE_PRINCIPAL_ALLOWLIST` | Optional comma-separated SPIFFE principals allowed to mint discharges. |

See [`.env.example`](.env.example) for a secret-free configuration template. Do not place a master key, certificate private key, policy secret, or runtime state in this repository.

## Client configuration

Every client connection needs these variables:

```text
SECRET_BROKER_ENDPOINT
SECRET_BROKER_CLIENT_CERT
SECRET_BROKER_CLIENT_KEY
SECRET_BROKER_CLIENT_CA_CERT
SECRET_BROKER_CLIENT_SERVER_NAME
```

`SECRET_BROKER_ENDPOINT` must be an `https` URL without user info, query, fragment, or non-root path. `SECRET_BROKER_CLIENT_TIMEOUT_SECS` is optional and defaults to 10 seconds.

For the default `enforced` mode, also provide:

```text
SECRET_BROKER_CLIENT_POLICY_FILE
SECRET_BROKER_CLIENT_SUBJECTS
SECRET_BROKER_PCCS_URL
```

The policy file is JSON. It must name a policy and constrain at least one measured identity: a TDX `allowed_mrtd`, a complete SGX `allowed_mrenclave`/`allowed_mrsigner` pair, or an `expected_compose_hash`. For example:

```json
{
  "policy_name": "broker-tdx-v1",
  "allowed_mrtd": ["replace-with-approved-lowercase-hex-measurement"],
  "allowed_mrenclave": [],
  "allowed_mrsigner": [],
  "min_isvsvn": null,
  "expected_compose_hash": null
}
```

The subject allowlist is a comma-separated list of certificate common names. Empty or duplicate entries are rejected.

For a controlled local-mTLS test, set `SECRET_BROKER_CLIENT_MODE=local` and use a loopback `https` endpoint. Do not provide the enforced-mode policy, subject, or PCCS variables in that mode.

## Public-client use

The public entry point is `SecretBrokerClient::from_env()` or `SecretBrokerClient::connect(config)`:

```rust
use secret_broker_client::{
    SecretBrokerClient, UnwrapSecretV2Params, WrapV2Params,
};

let client = SecretBrokerClient::from_env().await?;
let wrapped = client
    .wrap_bytes_v2(b"secret", WrapV2Params::default())
    .await?;
let plaintext = client
    .unwrap_secret_v2(UnwrapSecretV2Params {
        handle: wrapped.handle,
        redeem_token: Some(wrapped.redeem_token),
        ..Default::default()
    })
    .await?;
```

Third-party attenuation returns `AttenuateHandleV2Result`, which contains the attenuated handle and an optional opaque `third_party_caveat_id`. Supply that ID unchanged with the **attenuated handle** to `mint_discharge`.

## Lifecycle and persistence

V2 secrets have three lifecycle classes:

- `SingleUseUnwrap`: one successful unwrap consumes the redeem token.
- `RenewableLease`: repeated unwraps are allowed while its lease is active and it is not revoked.
- `ServiceBootstrap`: startup-oriented lifecycle with distinct audit semantics.

Sealed records persist encrypted envelopes, redemption material, caveat state, and the public verification material for their ML-DSA envelope signatures. Envelope signature verification uses the persisted public key, so a valid renewable secret can be verified and unwrapped after a broker restart without relying on a recreated process-local signing-key cache. Signing-key expiry is still enforced.

## Verified local behavior

A disposable loopback mTLS run exercised the public client against the standalone broker in explicit software-backed mode. It verified:

1. mint AEAD key then unwrap;
2. wrap then unwrap;
3. attenuate then mint discharge then discharge-authorized unwrap;
4. encrypt then decrypt, with ciphertext distinct from the selected plaintext marker;
5. key generation then public-key retrieval; and sign then verify;
6. the plaintext marker was absent from the temporary sealed-state and crypto-state files; and
7. a broker restart against the same sealed state successfully unwrapped the renewable-lease secret.

This is an integration result, not a claim of formal security certification or production readiness.

## Research context

These sources informed the concepts used here; they do not independently validate this implementation.

- Birgisson et al., [*Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud*](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/), NDSS 2014. The paper describes chained-HMAC capabilities and contextual caveats, the model behind handle attenuation and third-party discharges.
- Knauth et al., [*Integrating Remote Attestation with Transport Layer Security*](https://arxiv.org/abs/1801.05863), 2018. It describes binding remote-attestation evidence to standard TLS setup without changing TLS itself, the design context for the enforced RA-TLS client path.
- NIST, [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final), 2024. It specifies ML-KEM and its three parameter sets.
- NIST, [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final), 2024. It specifies ML-DSA, used by the implementation's Dilithium/ML-DSA signing path.
- Shamir, [*How to Share a Secret*](https://doi.org/10.1145/359168.359176), 1979. It defines the polynomial secret-sharing construction used for threshold redeem material.
- Feldman, [*A Practical Scheme for Non-interactive Verifiable Secret Sharing*](https://doi.org/10.1109/SFCS.1987.4), 1987. It provides the commitment model used to verify threshold shares.
- IETF, [RFC 5705: Keying Material Exporters for TLS](https://www.rfc-editor.org/rfc/rfc5705), 2010. It defines the exporter construction used to bind broker requests to their authenticated TLS session.

## Security and disclosure

See [`SECURITY.md`](SECURITY.md) for the supported reporting channel, threat boundaries, and handling guidance. Never include live secrets, private keys, macaroons, discharge tokens, or database URLs in a report.

## Scope boundaries

- This repository does not create or distribute CA material, private keys, PCCS collateral, measurement policies, or runtime state.
- PostgreSQL credential issuance is unavailable unless the broker is explicitly configured with its required PostgreSQL administration settings.
- A remote endpoint cannot use local mode. Invalid trust configuration returns an error; it is not silently downgraded.
- This repository is published for inspection without a software license; all rights are reserved unless and until the owner adds one.
