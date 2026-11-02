# Join-surface notes

The join surface is not covered by the NXS wire specification or fixtures. It
was learned from `node-nethernet`, `df-mc/go-nethernet`, and Bedrock clients.

## Implemented shape

- `GET /v1/join` returns server-list JSON: `name`, `protocol`, `version`,
  `level`, `players`, `maxPlayers`, `gameType`.
- `POST /v1/join/{clientNetworkId}` accepts `application/sdp` and returns an
  SDP answer.
- The offer's `a=identity` assertion is verified, including the detached ES384
  proof over the offer DTLS fingerprints.
- The answer ICE ufrag is the admission token (`NXS1` prefix); the answer ICE
  password is derived from the host's admission secret.
- The answer includes a provider-signed server identity assertion, host DTLS
  fingerprint, SCTP parameters and stored candidates.
- `node-nethernet`'s `verifyServerIdentity` accepts a generated answer.

## What is known

- The provider answers a join with an SDP answer synthesised from the stored host
  profile. It does not proxy media and does not relay SDP.
- The answer must use the profile's `sctpPort`, `maxMessageSize`, DTLS
  fingerprint and candidates.
- The client must carry the admission token in its first STUN packet, in the ICE
  username (`NXS1` prefix).
- A stale profile produces an unjoinable server. Version profiles and refuse to
  route on an unaccepted revision.

## What is not known

- The `/v1/join` request and response JSON shape.
- Join-side SDP details beyond `sctp-port`, `max-message-size`, fingerprint and
  candidates.
- Current Bedrock client behaviour after RakNet was dropped on 2026-10-27.

Keep `src/join.rs` isolated so this shape can change without touching the core.
Gate 6 uses `PrismarineJS/node-nethernet` as the development client; gate 7 is a
real Bedrock client and is the actual completion criterion.

## Downstream note

`nekoy3/Network-nethernet-turn` adds an experimental
`nethernet.predictSignalingCandidate` step before trickled remote candidates are
delivered (default true). It overlaps upstream `SdpUtil.inferredPeerCandidates`
and no independent benefit has been established. The repository is useful for
reading what someone thought worth changing; its fixtures are not the source of
truth. See `vendor/PROVENANCE.md`.
