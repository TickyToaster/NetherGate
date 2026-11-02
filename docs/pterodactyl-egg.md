# Pterodactyl egg requirements — `nxsd`

Status: requirements only. This document specifies the egg to be implemented; it
is not the egg JSON yet.

## Purpose

Package `nxsd` as a Pterodactyl/Wings server so an operator can run one NXS v1
provider instance with a persistent SQLite store, configurable public origin,
and a single exposed HTTP port.

## Deployment model

- One Pterodactyl server = one `nxsd` process = one SQLite database.
- TLS is terminated by an external reverse proxy (Caddy, nginx, Cloudflare
  Tunnel, or the panel host's proxy).
- The egg exposes plain HTTP only on an allocated TCP port. It must not be
  exposed directly to Bedrock clients.
- Gameplay/NetherNet host traffic is out of scope; the egg runs only the
  coordinator.

## Functional requirements

| ID | Requirement |
|---|---|
| FR-1 | Install a Linux x86-64 `nxsd` binary into `/home/container`. |
| FR-2 | Make the binary executable by the container user. |
| FR-3 | Start exactly one `nxsd` process as PID 1's child, without a shell wrapper that ignores signals. |
| FR-4 | Read all runtime configuration from environment variables; no generated TOML is required. |
| FR-5 | Persist SQLite at `/home/container/nxsd.db` by default, overridable via `NXSD_DATABASE_PATH`. |
| FR-6 | Create the database and apply migrations on first start. |
| FR-7 | Expose `/healthz`, `/.well-known/nethernet-external-signaling`, `GET /v1/join`, and `POST /v1/join/{id}` on the allocated port. |
| FR-8 | Bind to `0.0.0.0` inside the container on the port assigned by Pterodactyl. |
| FR-9 | Stop gracefully on `SIGTERM`; allow at least 30 seconds before `SIGKILL`. |
| FR-10 | Preserve the database across restarts and reinstalls unless the operator explicitly deletes it. |
| FR-11 | Log to stdout/stderr so Wings captures output. |
| FR-12 | Support the full set of provider variables listed below. |

## Required variables

| Variable | Default | User viewable | User editable | Rules |
|---|---|---|---|---|
| `NXSD_PUBLIC_ORIGIN` | — (required) | yes | yes | Canonical `https://host[:port]` origin; no path, query, fragment, or trailing slash |
| `NXSD_LISTEN` | `0.0.0.0:8080` | yes | yes | `host:port`; must match the allocated container port |
| `NXSD_DATABASE_PATH` | `/home/container/nxsd.db` | yes | yes | Absolute path under `/home/container` |
| `NXSD_POW_DIFFICULTY` | `12` | yes | yes | Integer `0`–`24`; use low values only for local testing |
| `NXSD_LOG` | `nxsd=info` | yes | yes | `tracing` filter string |
| `NXSD_PORT` | `8080` | yes | no | Injected from the Pterodactyl allocation if the startup script composes `NXSD_LISTEN` |

`NXSD_PUBLIC_ORIGIN` is mandatory and must equal the origin clients use. The
startup must fail fast if it is missing or noncanonical.

## Startup requirements

- Startup command must exec the binary directly, or use an entrypoint that
  forwards `SIGTERM`.
- Recommended form:
  ```sh
  ./nxsd
  ```
  with `NXSD_LISTEN=0.0.0.0:${SERVER_PORT}` set by the egg.
- Do not run `cargo run`, rebuild on start, or require a Rust toolchain.
- Do not run as root.
- Do not require a writable `/usr` or `/etc`.

## Install requirements

- Target base image: a Debian-family Pterodactyl yolk with glibc, not Alpine.
- The egg must obtain the binary from one of:
  1. a release URL variable with a pinned version, or
  2. a pre-uploaded binary in the server volume.
- If downloading, verify a SHA-256 checksum and fail installation on mismatch.
- Installation must not require network access at runtime after the binary is
  installed.
- Reinstalling must not silently delete an existing `nxsd.db`.

Suggested release layout:

```text
nxsd-linux-x86_64-v<version>
nxsd-linux-x86_64-v<version>.sha256
```

## Networking requirements

- The egg requires one TCP allocation for plain HTTP.
- The reverse proxy must forward to `http://<node>:<allocation>` and preserve the
  `Host` header.
- The proxy must be configured with the same public origin as
  `NXSD_PUBLIC_ORIGIN`.
- WebSocket support is not required for the current MVP because `control-v1` is
  not implemented.
- No UDP allocation is required by `nxsd` itself.

## TLS requirements

- The client-facing endpoint must present a certificate trusted by the Bedrock
  client device.
- Acceptable: public ACME certificate, or a private CA whose root is installed
  on the client.
- Do not use a Caddy internal CA for production clients unless the root is
  explicitly installed on every client.
- The egg must document that plain `http://` is only valid for
  `localhost`/loopback testing.

## Persistence and backup requirements

- Persistent files:
  - `nxsd.db`
  - `nxsd.db-wal`
  - `nxsd.db-shm`
- Backups must either stop the server first or include all three files.
- Upgrades must preserve the database and run forward-only migrations.
- Rollback must be possible by restoring the previous database backup; there is
  no automatic down-migration.

## Security requirements

- Run as the unprivileged container user.
- Never embed provider private keys, admission secrets, or database contents in
  egg variables or logs.
- Do not expose the SQLite file or the plain HTTP port publicly.
- `NXSD_PUBLIC_ORIGIN` must be validated at startup.
- The egg must not enable privileged mode or mount the Docker socket.

## Resource requirements

Minimum:

- 128 MiB RAM
- 0.25 vCPU
- 50 MiB disk plus database size

`nxsd` is I/O-light; SQLite growth is driven by instances, profiles, leases and
idempotency records. No GPU, audio, or special capabilities.

## Observability requirements

- Startup log must state the bind address and public origin.
- The egg should expose `/healthz` for external monitoring; Wings does not
  perform HTTP health checks itself.
- Operators must be able to see registration, heartbeat and join failures in
  the console.
- Log level must be configurable through `NXSD_LOG`.

## Compatibility requirements

- Linux x86-64, glibc 2.31 or newer.
- Pterodactyl Wings 1.x egg schema.
- Pterodactyl backups enabled if the database must survive node loss.
- Current `nxsd` uses env overrides `NXSD_LISTEN`, `NXSD_PUBLIC_ORIGIN`,
  `NXSD_DATABASE_PATH`, `NXSD_LOG`, and `NXSD_POW_DIFFICULTY`.
- The binary is dynamically linked; Alpine/musl images are unsupported unless a
  musl build is produced.

## Acceptance criteria

1. Importing the egg and creating a server succeeds without manual shell work.
2. Starting the server creates `nxsd.db` and serves `/healthz` on the allocated
   port.
3. `/.well-known/nethernet-external-signaling` returns the configured
   `public_origin`.
4. Restarting preserves registration and inventory data.
5. `SIGTERM` from Wings stops the process cleanly without a forced kill.
6. Reinstalling with "delete files" off preserves the database.
7. A request through the external TLS proxy reaches `/healthz` and
   `GET /v1/join`.
8. Invalid or missing `NXSD_PUBLIC_ORIGIN` prevents startup with a clear error.
9. Backups taken while stopped restore to a working database.
10. No root, privileged mode, or Docker socket access is required.

## Out of scope for the first egg

- Bundling Caddy or another TLS terminator inside the server container.
- Running a NetherNet host or gameplay UDP listener.
- Multi-tenant services or multiple `nxsd` instances in one server.
- `control-v1` WebSocket, assisted joins, connectivity diagnostics.
- Automatic binary updates.
- Geo-routing or fleet management.

## Open decisions

1. Artifact source: GitHub release, object storage, or manual upload.
2. Whether to ship a Caddy-in-container variant later.
3. Whether the egg should default `NXSD_POW_DIFFICULTY` to `12` or require the
   operator to set it explicitly.
4. Whether to expose a `NXSD_CONFIG` variable for operators who prefer TOML.
