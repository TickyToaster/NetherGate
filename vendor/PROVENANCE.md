# Vendored upstream provenance

These files are copied verbatim from the NetherNet external-signaling
specification. They are test and reference material only; they are not modified
by this repository.

- **Repository:** <https://github.com/CloudburstMC/Network>
- **Commit:** `35cfff20cc720ebb4f54237b4ab626c727039f10`
- **Commit date:** 2026-10-30
- **Commit signature:** SSH signature by `irrld <irrelevantdev@outlook.com>`;
  GitHub reports the signature as valid and verified.
- **Upstream path:** `docs/external-signaling/`
- **License:** Apache-2.0 (see `upstream/LICENSE`)

`scripts/sync-fixtures.sh` pins both the git blob SHA and the SHA-256 of every
file. Either mismatch aborts the sync, so a refresh is a reviewed diff rather
than a silent replacement. Run `scripts/sync-fixtures.sh --check` to verify an
existing vendor tree without network access.

| File | Git blob SHA | SHA-256 |
|---|---|---|
| `LICENSE` | `5e6d1ba954fc4e6ababcec4844d398c9ca79b6a5` | `11c52cd9427fa5092c35697b54f651f839f9edb010932fc926e5b6bd003192a2` |
| `docs/external-signaling/README.md` | `43af52ad7786b72a9a59297ad47a137f978b80c0` | `20a813a5c1c3513bd4f48000eb66b4945479279f614605df9d099ebc95cb85ac` |
| `docs/external-signaling/wire-reference.md` | `d46d40738959753971e65b8c6e1b96bd5b0b7fc2` | `fb8e24e7dd1282d35e3d76008eb054345a6d3c8e7e1fb528cd2b5c4e26ad199b` |
| `docs/external-signaling/nxs-v1.schema.json` | `5706ac1a5c97f56af90d0858ae4a11ce7dedaa97` | `de18510c7add6432b613b5ffc796988aead523f03687b50dd42592cddbf14b4a` |
| `docs/external-signaling/fixtures/origins.fixtures.json` | `ab4e10bf683c9dfe599f25cfe93237ce73b89a7b` | `674e7f1fc47cbb1c05d63da1ce15e8744464d2244a415a835c1b6edc4823768c` |
| `docs/external-signaling/fixtures/nxs-v1.fixtures.json` | `b8fffb600004e30e942be9bb0b0cae9bc82104a9` | `7f05013fea19a4c0229226a58dd4f41203a736c7effc4351eb6b25970707cc39` |
| `docs/external-signaling/fixtures/stateless-admission-v1.fixtures.json` | `57032abfffd5fb6329d073abf7c58e0094079d0c` | `9eaa8266a7a0455f406a0f72c65f13d9f5d161569dc4577af6fd3a0b6782b4f6` |
| `docs/external-signaling/fixtures/cloudburst-protocol-vectors.v1.json` | `29c10ab4a088542c6a9295c0387c01c516f98c45` | `2bd4c3305a0911f2d4a1166f1c6760ed6979c5af551cbd9660e9badd1f7fb993` |
| `docs/external-signaling/fixtures/provenance.json` | `d2288c24761721fbe5f2ebe76f1c907f417110fd` | `d88e1ddf6804abd23581b5d876c9295bed6b2d6fd6bc54a2563a8ca6d55fcf4d` |

Upstream `provenance.json` vouches for two of these files by SHA-256:

- `stateless-admission-v1.fixtures.json` — `9eaa8266a7a0455f406a0f72c65f13d9f5d161569dc4577af6fd3a0b6782b4f6`
- `cloudburst-protocol-vectors.v1.json` — `2bd4c3305a0911f2d4a1166f1c6760ed6979c5af551cbd9660e9badd1f7fb993`

`tests/vectors.rs` verifies those two values on every test run.

## Downstream copy

`nekoy3/Network-nethernet-turn` is an unofficial downstream copy. It is not a
source of truth for vendored bytes. Its `DOWNSTREAM-CHANGES.md` records an
experimental `nethernet.predictSignalingCandidate` change (default true) that
overlaps upstream `SdpUtil.inferredPeerCandidates`; keep it in mind when
investigating `/v1/join`, but do not copy its fixtures.
