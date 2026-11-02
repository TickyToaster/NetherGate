# NetherGate

`nxsd` is an **NXS v1 provider**: an HTTPS coordinator for NetherNet hosts.

It holds an inventory of registered agents, mints admission tokens, and answers
client joins with an SDP answer synthesised from each agent's stored profile. It
never handles gameplay traffic and is not a media server.

This is an implementation of the protocol, not a clone of any particular
provider. It is not affiliated with or endorsed by CloudburstMC, Mojang or
Microsoft.

## Status

Gates 1-6 are complete. Canonical origins, `JSON.stringify`-compatible payloads,
P-384 JWK thumbprints and ES384 signatures pass the vendored
`origins.fixtures.json` and `nxs-v1.fixtures.json` vectors.

Stateless admission passes `stateless-admission-v1.fixtures.json`: AEAD key
derivation, token sealing/opening, ICE ufrag, ICE password and identity binding
match the expected bytes.

Anonymous `register`/`complete` with proof of work, persistent identity,
generation fencing, and recovery (including recovery by saved challenge ID) are
implemented.

`heartbeat` now authenticates signed operational requests, enforces timestamp,
generation and sequence rules, stores host profiles and leases, and reports
readiness. A background sweep expires leases and flips instances non-routable.

Admission-key epochs are implemented: provisioning through
`admissionKeyRequestId`, acknowledgement through `installedAdmissionKeyIds`,
profile/epoch consistency checks, retirement deadlines, and a sweep that erases
retired secrets.

The HTTP join surface matches the client-observed shape: `GET /v1/join` returns
server-list JSON, and `POST /v1/join/{clientNetworkId}` verifies the offer's
`a=identity` proof of possession, mints an admission token into the answer ICE
ufrag, and synthesises a signed SDP answer from the host profile. `outcomes`
still returns `501`.

## Build and run

```sh
cargo build
cargo run
curl -i http://localhost:8080/healthz
curl -s http://localhost:8080/.well-known/nethernet-external-signaling
```

Configuration loads from `config/nxsd.toml` if present, otherwise defaults.
Environment variables override the file:

| Variable | Default |
|---|---|
| `NXSD_LISTEN` | `127.0.0.1:8080` |
| `NXSD_PUBLIC_ORIGIN` | `http://localhost:8080` |
| `NXSD_DATABASE_PATH` | `nxsd.db` |
| `NXSD_LOG` | `nxsd=info` |
| `NXSD_CONFIG` | `config/nxsd.toml` |

See `config/nxsd.example.toml`.

## Docker

TLS terminates at Caddy; `nxsd` stays on the internal network and is not
published directly.

```sh
cd docker
docker compose up --build
curl -k https://localhost/healthz
```

The default Caddyfile uses its internal CA and site address `localhost`. For a
real deployment set `NXSD_SITE_ADDRESS` to the provider's hostname and replace
`tls internal` with normal ACME/public TLS. The configured public origin must be
canonical and must match the address clients use.

## Tests

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
./scripts/sync-fixtures.sh --check
```

`tests/vectors.rs` verifies the two SHA-256 values that upstream
`provenance.json` publishes, so a corrupted or silently swapped fixture fails CI.
`scripts/sync-fixtures.sh` additionally pins the git blob SHA of every vendored
file. See `vendor/PROVENANCE.md` for the exact upstream commit and hashes.

## Layout

| Path | Purpose |
|---|---|
| `src/origin.rs` | Canonical origin validation (done) |
| `src/canonical.rs` | `JSON.stringify`-compatible payload joining (done) |
| `src/jwk.rs` | P-384 JWK, thumbprint, ES384 (done) |
| `src/proofs.rs` | Completion/operation/rotate proofs and PoW (done) |
| `src/encoding.rs` | Canonical base64url and standard base64 |
| `src/admission.rs` | AEAD token, ufrag, ICE password, binding (done) |
| `src/registration.rs` | Register, complete, PoW, recovery (done) |
| `src/heartbeat.rs` | Signed heartbeat, profiles, leases, key epochs (done) |
| `src/store.rs` | SQLite generations, sequences, inventory |
| `src/join.rs` | Join listing, offer verification, SDP synthesis (done) |

Remaining gates and the unknown join surface are tracked in
`docs/join-notes.md`. Pterodactyl packaging requirements are in
`docs/pterodactyl-egg.md`.
