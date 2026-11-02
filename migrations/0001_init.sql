CREATE TABLE services (
    service_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE TABLE instances (
    instance_id TEXT PRIMARY KEY,
    registration_id TEXT NOT NULL UNIQUE,
    service_id TEXT REFERENCES services(service_id),
    key_id TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    label TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deregistered')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX instances_service_id ON instances(service_id);

CREATE TABLE challenges (
    challenge_id TEXT PRIMARY KEY,
    registration_id TEXT,
    instance_id TEXT,
    mode TEXT NOT NULL CHECK (mode IN ('new-service', 'attach-instance', 'recover')),
    nonce TEXT NOT NULL,
    audience TEXT NOT NULL,
    thumbprint TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    context_json TEXT NOT NULL,
    context_digest TEXT NOT NULL,
    pow_difficulty INTEGER NOT NULL CHECK (pow_difficulty BETWEEN 0 AND 24),
    authorization_id TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    server_time INTEGER NOT NULL,
    consumed_at INTEGER,
    result_registration_id TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX challenges_registration_id ON challenges(registration_id);
CREATE INDEX challenges_instance_id ON challenges(instance_id);

CREATE TABLE generations (
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    lease_generation INTEGER NOT NULL,
    machine_key_id TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    PRIMARY KEY (instance_id, lease_generation)
);

CREATE TABLE request_sequences (
    instance_id TEXT NOT NULL,
    lease_generation INTEGER NOT NULL,
    last_sequence INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (instance_id, lease_generation),
    FOREIGN KEY (instance_id, lease_generation)
        REFERENCES generations(instance_id, lease_generation)
);

CREATE TABLE idempotency_records (
    instance_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_json TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (instance_id, idempotency_key)
);

CREATE TABLE admission_keys (
    key_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    request_id TEXT,
    secret TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'retiring', 'retired')),
    created_at INTEGER NOT NULL,
    acknowledged_at INTEGER,
    retire_after INTEGER
);

CREATE INDEX admission_keys_instance_id ON admission_keys(instance_id);
CREATE UNIQUE INDEX admission_keys_request_id ON admission_keys(instance_id, request_id);

CREATE TABLE host_profiles (
    revision TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(instance_id),
    incarnation TEXT NOT NULL,
    admission_key_id TEXT NOT NULL,
    dtls_fingerprint TEXT NOT NULL,
    sctp_port INTEGER NOT NULL CHECK (sctp_port BETWEEN 1 AND 65535),
    max_message_size INTEGER NOT NULL CHECK (max_message_size BETWEEN 1 AND 262144),
    profile_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX host_profiles_instance_id ON host_profiles(instance_id);

CREATE TABLE leases (
    instance_id TEXT PRIMARY KEY REFERENCES instances(instance_id),
    lease_generation INTEGER NOT NULL,
    profile_revision TEXT REFERENCES host_profiles(revision),
    routable INTEGER NOT NULL DEFAULT 0 CHECK (routable IN (0, 1)),
    accepting_players INTEGER NOT NULL DEFAULT 0 CHECK (accepting_players IN (0, 1)),
    capacity INTEGER NOT NULL DEFAULT 0 CHECK (capacity BETWEEN 0 AND 1000000),
    connected_players INTEGER NOT NULL DEFAULT 0 CHECK (connected_players BETWEEN 0 AND 1000000),
    sampled_at INTEGER,
    listing_name TEXT,
    listing_level TEXT,
    listing_max_players INTEGER,
    listing_game_type INTEGER,
    listing_protocol INTEGER,
    listing_version TEXT,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (instance_id, lease_generation)
        REFERENCES generations(instance_id, lease_generation)
);

CREATE TABLE outcome_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    ticket_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    reason TEXT,
    remote_address TEXT,
    remote_port INTEGER CHECK (remote_port IS NULL OR remote_port BETWEEN 1 AND 65535),
    received_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX outcome_events_dedup ON outcome_events (
    instance_id,
    ticket_id,
    stage,
    occurred_at,
    ifnull(reason, ''),
    ifnull(remote_address, ''),
    ifnull(remote_port, 0)
);

CREATE TABLE provider_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    private_d TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
