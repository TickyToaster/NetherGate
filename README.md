# NetherGate

nxs v1 endpoint, alternative to warden.cloud

## run it

```sh
cargo build
cargo run
curl -i http://localhost:8080/healthz
curl -s http://localhost:8080/.well-known/nethernet-external-signaling
```

Config at `config/nxsd.toml`

| Variable | Default |
|---|---|
| `NXSD_LISTEN` | `127.0.0.1:8080` |
| `NXSD_PUBLIC_ORIGIN` | `http://localhost:8080` |
| `NXSD_DATABASE_PATH` | `nxsd.db` |
| `NXSD_LOG` | `nxsd=info` |
| `NXSD_CONFIG` | `config/nxsd.toml` |
| `NXSD_DYNAMIC_ORIGINS` | `false` |

There's a `config/nxsd.example.toml`

```sh
cd docker
docker compose up --build
curl -k https://localhost/healthz
```


## layout

- `src/` provider code: `registration.rs`, `heartbeat.rs`, `join.rs`, plus the protocol helpers
- `migrations/` sqlite schema
- `tests/` fixture, protocol, and HTTP tests
- `vendor/` pinned upstream spec and fixtures
- `docker/` Caddy config and compose file
