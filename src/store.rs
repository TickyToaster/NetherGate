use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow};
use rusqlite::{Connection, OptionalExtension, params};

const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../migrations/0001_init.sql"))];

#[derive(Clone)]
pub struct Store {
    connection: Arc<Mutex<Connection>>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let connection = Connection::open(path.as_ref())
            .with_context(|| format!("opening sqlite database {}", path.as_ref().display()))?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> anyhow::Result<Self> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let _: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn migrate(&self) -> anyhow::Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;

        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
            );",
        )?;

        for (version, sql) in MIGRATIONS {
            let applied: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
                [version],
                |row| row.get(0),
            )?;
            if !applied {
                transaction.execute_batch(sql)?;
                transaction.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                    params![version, now_ms()],
                )?;
            }
        }

        transaction.commit()?;
        Ok(())
    }

    pub fn table_exists(&self, name: &str) -> anyhow::Result<bool> {
        let connection = self.lock()?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [name],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    fn lock(&self) -> anyhow::Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow!("sqlite connection mutex poisoned"))
    }
}

pub fn now_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

#[cfg(test)]
mod tests {
    use super::Store;

    #[test]
    fn migrations_are_idempotent() {
        let store = Store::open_in_memory().expect("store opens");
        store.migrate().expect("first migration");
        store.migrate().expect("second migration is a no-op");
    }

    #[test]
    fn creates_expected_tables() {
        let store = Store::open_in_memory().expect("store opens");
        store.migrate().expect("migrates");

        for table in [
            "schema_migrations",
            "services",
            "instances",
            "challenges",
            "generations",
            "request_sequences",
            "idempotency_records",
            "admission_keys",
            "host_profiles",
            "leases",
            "outcome_events",
        ] {
            assert!(store.table_exists(table).expect("query"), "missing {table}");
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewChallenge {
    pub challenge_id: String,
    pub registration_id: Option<String>,
    pub instance_id: Option<String>,
    pub mode: String,
    pub nonce: String,
    pub audience: String,
    pub thumbprint: String,
    pub public_jwk: String,
    pub context_json: String,
    pub context_digest: String,
    pub pow_difficulty: u8,
    pub authorization_id: String,
    pub expires_at: i64,
    pub server_time: i64,
}

#[derive(Debug, Clone)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub registration_id: Option<String>,
    pub instance_id: Option<String>,
    pub mode: String,
    pub nonce: String,
    pub audience: String,
    pub thumbprint: String,
    pub public_jwk: String,
    pub context_json: String,
    pub context_digest: String,
    pub pow_difficulty: u8,
    pub authorization_id: String,
    pub expires_at: i64,
    pub server_time: i64,
    pub consumed_at: Option<i64>,
    pub result_registration_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InstanceRecord {
    pub instance_id: String,
    pub registration_id: String,
    pub service_id: Option<String>,
    pub key_id: String,
    pub public_jwk: String,
    pub label: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Copy)]
pub struct NewService<'a> {
    pub challenge_id: &'a str,
    pub now: i64,
    pub service_id: &'a str,
    pub instance_id: &'a str,
    pub registration_id: &'a str,
    pub key_id: &'a str,
    pub label: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum CompleteError {
    #[error("challenge not found")]
    NotFound,
    #[error("completion already consumed")]
    AlreadyConsumed,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<rusqlite::Error> for CompleteError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl Store {
    pub fn add_challenge(&self, challenge: &NewChallenge) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO challenges (
                challenge_id, registration_id, instance_id, mode, nonce, audience,
                thumbprint, public_jwk, context_json, context_digest, pow_difficulty,
                authorization_id, expires_at, server_time, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                challenge.challenge_id,
                challenge.registration_id,
                challenge.instance_id,
                challenge.mode,
                challenge.nonce,
                challenge.audience,
                challenge.thumbprint,
                challenge.public_jwk,
                challenge.context_json,
                challenge.context_digest,
                challenge.pow_difficulty,
                challenge.authorization_id,
                challenge.expires_at,
                challenge.server_time,
                now_ms(),
            ],
        )?;
        Ok(())
    }

    pub fn challenge(&self, challenge_id: &str) -> anyhow::Result<Option<ChallengeRecord>> {
        let connection = self.lock()?;
        let challenge = connection
            .query_row(
                "SELECT challenge_id, registration_id, instance_id, mode, nonce, audience,
                        thumbprint, public_jwk, context_json, context_digest, pow_difficulty,
                        authorization_id, expires_at, server_time, consumed_at, result_registration_id
                 FROM challenges WHERE challenge_id = ?1",
                [challenge_id],
                challenge_from_row,
            )
            .optional()?;
        Ok(challenge)
    }

    pub fn instance_by_registration(
        &self,
        registration_id: &str,
    ) -> anyhow::Result<Option<InstanceRecord>> {
        let connection = self.lock()?;
        let instance = connection
            .query_row(
                "SELECT instance_id, registration_id, service_id, key_id, public_jwk, label, status
                 FROM instances WHERE registration_id = ?1",
                [registration_id],
                instance_from_row,
            )
            .optional()?;
        Ok(instance)
    }

    pub fn instance_by_id(&self, instance_id: &str) -> anyhow::Result<Option<InstanceRecord>> {
        let connection = self.lock()?;
        let instance = connection
            .query_row(
                "SELECT instance_id, registration_id, service_id, key_id, public_jwk, label, status
                 FROM instances WHERE instance_id = ?1",
                [instance_id],
                instance_from_row,
            )
            .optional()?;
        Ok(instance)
    }

    pub fn registration_for_challenge(&self, challenge_id: &str) -> anyhow::Result<Option<String>> {
        let connection = self.lock()?;
        let registration = connection
            .query_row(
                "SELECT result_registration_id FROM challenges WHERE challenge_id = ?1",
                [challenge_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(registration.flatten())
    }

    pub fn finish_new_service(&self, registration: NewService<'_>) -> Result<(), CompleteError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let public_jwk =
            consume_challenge(&transaction, registration.challenge_id, registration.now)?;

        transaction.execute(
            "INSERT INTO services (service_id, created_at) VALUES (?1, ?2)",
            params![registration.service_id, registration.now],
        )?;
        transaction.execute(
            "INSERT INTO instances (
                instance_id, registration_id, service_id, key_id, public_jwk, label,
                status, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?7)",
            params![
                registration.instance_id,
                registration.registration_id,
                registration.service_id,
                registration.key_id,
                public_jwk,
                registration.label,
                registration.now
            ],
        )?;
        transaction.execute(
            "INSERT INTO generations (instance_id, lease_generation, machine_key_id, started_at)
             VALUES (?1, 1, ?2, ?3)",
            params![
                registration.instance_id,
                registration.key_id,
                registration.now
            ],
        )?;
        transaction.execute(
            "UPDATE challenges SET result_registration_id = ?2 WHERE challenge_id = ?1",
            params![registration.challenge_id, registration.registration_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn finish_recovery(
        &self,
        challenge_id: &str,
        now: i64,
        instance_id: &str,
    ) -> Result<i64, CompleteError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        consume_challenge(&transaction, challenge_id, now)?;

        let generation: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(lease_generation), 0) + 1
             FROM generations WHERE instance_id = ?1",
            [instance_id],
            |row| row.get(0),
        )?;
        let key_id: String = transaction.query_row(
            "SELECT key_id FROM instances WHERE instance_id = ?1",
            [instance_id],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO generations (instance_id, lease_generation, machine_key_id, started_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![instance_id, generation, key_id, now],
        )?;
        transaction.execute("DELETE FROM leases WHERE instance_id = ?1", [instance_id])?;
        transaction.commit()?;
        Ok(generation)
    }
}

fn consume_challenge(
    transaction: &rusqlite::Transaction<'_>,
    challenge_id: &str,
    now: i64,
) -> Result<String, CompleteError> {
    let row = transaction
        .query_row(
            "SELECT consumed_at, public_jwk FROM challenges WHERE challenge_id = ?1",
            [challenge_id],
            |row| {
                let consumed_at: Option<i64> = row.get(0)?;
                let public_jwk: String = row.get(1)?;
                Ok((consumed_at, public_jwk))
            },
        )
        .optional()?;

    match row {
        None => Err(CompleteError::NotFound),
        Some((Some(_), _)) => Err(CompleteError::AlreadyConsumed),
        Some((None, public_jwk)) => {
            transaction.execute(
                "UPDATE challenges SET consumed_at = ?2 WHERE challenge_id = ?1",
                params![challenge_id, now],
            )?;
            Ok(public_jwk)
        }
    }
}

fn challenge_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChallengeRecord> {
    Ok(ChallengeRecord {
        challenge_id: row.get(0)?,
        registration_id: row.get(1)?,
        instance_id: row.get(2)?,
        mode: row.get(3)?,
        nonce: row.get(4)?,
        audience: row.get(5)?,
        thumbprint: row.get(6)?,
        public_jwk: row.get(7)?,
        context_json: row.get(8)?,
        context_digest: row.get(9)?,
        pow_difficulty: row.get(10)?,
        authorization_id: row.get(11)?,
        expires_at: row.get(12)?,
        server_time: row.get(13)?,
        consumed_at: row.get(14)?,
        result_registration_id: row.get(15)?,
    })
}

fn instance_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InstanceRecord> {
    Ok(InstanceRecord {
        instance_id: row.get(0)?,
        registration_id: row.get(1)?,
        service_id: row.get(2)?,
        key_id: row.get(3)?,
        public_jwk: row.get(4)?,
        label: row.get(5)?,
        status: row.get(6)?,
    })
}

#[derive(Debug, Clone)]
pub struct HostProfileInput {
    pub instance_id: String,
    pub revision: String,
    pub incarnation: String,
    pub admission_key_id: String,
    pub dtls_fingerprint: String,
    pub sctp_port: i64,
    pub max_message_size: i64,
    pub profile_json: String,
}

#[derive(Debug, Clone)]
pub struct HeartbeatUpdate {
    pub instance_id: String,
    pub lease_generation: i64,
    pub profile_revision: Option<String>,
    pub routable: bool,
    pub accepting_players: bool,
    pub capacity: i64,
    pub connected_players: i64,
    pub sampled_at: i64,
    pub listing_name: Option<String>,
    pub listing_level: Option<String>,
    pub listing_max_players: Option<i64>,
    pub listing_game_type: Option<i64>,
    pub listing_protocol: Option<i64>,
    pub listing_version: Option<String>,
    pub now: i64,
    pub lease_ms: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct RequestMeta<'a> {
    pub instance_id: &'a str,
    pub lease_generation: i64,
    pub sequence: i64,
    pub idempotency_key: &'a str,
    pub operation: &'a str,
    pub request_hash: &'a str,
    pub now: i64,
}

#[derive(Debug)]
pub enum RequestDecision {
    Accepted,
    Replay(String),
    InFlight,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("stale generation")]
    StaleGeneration,
    #[error("sequence not newer than last accepted")]
    Sequence,
    #[error("idempotency key reused with a different request")]
    IdempotencyConflict,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<rusqlite::Error> for RequestError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl Store {
    pub fn latest_generation(&self, instance_id: &str) -> anyhow::Result<Option<i64>> {
        let connection = self.lock()?;
        let generation = connection
            .query_row(
                "SELECT MAX(lease_generation) FROM generations WHERE instance_id = ?1",
                [instance_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(generation.flatten())
    }

    pub fn accept_request(&self, meta: RequestMeta<'_>) -> Result<RequestDecision, RequestError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;

        let latest: Option<i64> = transaction
            .query_row(
                "SELECT MAX(lease_generation) FROM generations WHERE instance_id = ?1",
                [meta.instance_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if latest != Some(meta.lease_generation) {
            return Err(RequestError::StaleGeneration);
        }

        let existing: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT request_hash, response_json FROM idempotency_records
                 WHERE instance_id = ?1 AND idempotency_key = ?2",
                params![meta.instance_id, meta.idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_hash, response)) = existing {
            if stored_hash != meta.request_hash {
                return Err(RequestError::IdempotencyConflict);
            }
            return Ok(match response {
                Some(response) => RequestDecision::Replay(response),
                None => RequestDecision::InFlight,
            });
        }

        let last_sequence: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(last_sequence), 0) FROM request_sequences
                 WHERE instance_id = ?1 AND lease_generation = ?2",
                params![meta.instance_id, meta.lease_generation],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if meta.sequence <= last_sequence {
            return Err(RequestError::Sequence);
        }

        transaction.execute(
            "INSERT INTO request_sequences (instance_id, lease_generation, last_sequence, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (instance_id, lease_generation)
             DO UPDATE SET last_sequence = excluded.last_sequence, updated_at = excluded.updated_at",
            params![meta.instance_id, meta.lease_generation, meta.sequence, meta.now],
        )?;
        transaction.execute(
            "INSERT INTO idempotency_records (
                instance_id, idempotency_key, operation, request_hash, response_json,
                created_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)",
            params![
                meta.instance_id,
                meta.idempotency_key,
                meta.operation,
                meta.request_hash,
                meta.now,
                meta.now + 3_600_000
            ],
        )?;
        transaction.commit()?;
        Ok(RequestDecision::Accepted)
    }

    pub fn store_request_response(
        &self,
        instance_id: &str,
        idempotency_key: &str,
        response_json: &str,
    ) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "UPDATE idempotency_records SET response_json = ?3
             WHERE instance_id = ?1 AND idempotency_key = ?2",
            params![instance_id, idempotency_key, response_json],
        )?;
        Ok(())
    }

    pub fn store_profile(&self, profile: &HostProfileInput, now: i64) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO host_profiles (
                revision, instance_id, incarnation, admission_key_id, dtls_fingerprint,
                sctp_port, max_message_size, profile_json, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (revision) DO NOTHING",
            params![
                profile.revision,
                profile.instance_id,
                profile.incarnation,
                profile.admission_key_id,
                profile.dtls_fingerprint,
                profile.sctp_port,
                profile.max_message_size,
                profile.profile_json,
                now
            ],
        )?;
        Ok(())
    }

    pub fn profile_revision_exists(
        &self,
        instance_id: &str,
        revision: &str,
    ) -> anyhow::Result<bool> {
        let connection = self.lock()?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM host_profiles WHERE instance_id = ?1 AND revision = ?2)",
            params![instance_id, revision],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    pub fn record_heartbeat(&self, update: &HeartbeatUpdate) -> anyhow::Result<()> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO leases (
                instance_id, lease_generation, profile_revision, routable,
                accepting_players, capacity, connected_players, sampled_at,
                listing_name, listing_level, listing_max_players,
                listing_game_type, listing_protocol, listing_version,
                expires_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT (instance_id) DO UPDATE SET
                lease_generation = excluded.lease_generation,
                profile_revision = excluded.profile_revision,
                routable = excluded.routable,
                accepting_players = excluded.accepting_players,
                capacity = excluded.capacity,
                connected_players = excluded.connected_players,
                sampled_at = excluded.sampled_at,
                listing_name = excluded.listing_name,
                listing_level = excluded.listing_level,
                listing_max_players = excluded.listing_max_players,
                listing_game_type = excluded.listing_game_type,
                listing_protocol = excluded.listing_protocol,
                listing_version = excluded.listing_version,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at",
            params![
                update.instance_id,
                update.lease_generation,
                update.profile_revision,
                update.routable,
                update.accepting_players,
                update.capacity,
                update.connected_players,
                update.sampled_at,
                update.listing_name,
                update.listing_level,
                update.listing_max_players,
                update.listing_game_type,
                update.listing_protocol,
                update.listing_version,
                update.now + update.lease_ms,
                update.now
            ],
        )?;
        Ok(())
    }

    pub fn instance_routable(&self, instance_id: &str, now: i64) -> anyhow::Result<bool> {
        let connection = self.lock()?;
        let routable = connection
            .query_row(
                "SELECT routable = 1 AND expires_at > ?2 FROM leases WHERE instance_id = ?1",
                params![instance_id, now],
                |row| row.get(0),
            )
            .optional()?;
        Ok(routable.unwrap_or(false))
    }

    pub fn expire_leases(&self, now: i64) -> anyhow::Result<usize> {
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE leases SET routable = 0 WHERE routable = 1 AND expires_at <= ?1",
            [now],
        )?;
        Ok(changed)
    }

    pub fn lease_profile_revision(&self, instance_id: &str) -> anyhow::Result<Option<String>> {
        let connection = self.lock()?;
        let revision = connection
            .query_row(
                "SELECT profile_revision FROM leases WHERE instance_id = ?1",
                [instance_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(revision.flatten())
    }
}

#[derive(Debug, Clone)]
pub struct AdmissionKeyRecord {
    pub key_id: String,
    pub secret: String,
    pub state: String,
    pub retire_after: Option<i64>,
}

#[derive(Debug)]
pub enum MintOutcome {
    New { key_id: String, secret: String },
    Existing { key_id: String },
}

#[derive(Debug)]
pub struct AckResult {
    pub active_key: Option<String>,
    pub retirements: Vec<(String, i64)>,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionKeyError {
    #[error("unknown admission key")]
    UnknownKey,
    #[error("admission key cannot be acknowledged")]
    NotAckable,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<rusqlite::Error> for AdmissionKeyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl Store {
    pub fn mint_admission_key(
        &self,
        instance_id: &str,
        request_id: &str,
        now: i64,
    ) -> anyhow::Result<MintOutcome> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;

        let existing: Option<String> = transaction
            .query_row(
                "SELECT key_id FROM admission_keys WHERE instance_id = ?1 AND request_id = ?2",
                params![instance_id, request_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(key_id) = existing {
            return Ok(MintOutcome::Existing { key_id });
        }

        transaction.execute(
            "UPDATE admission_keys SET state = 'retired', secret = ''
             WHERE instance_id = ?1 AND state = 'pending'",
            [instance_id],
        )?;

        let key_id = loop {
            let candidate = random_key_id();
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_keys WHERE key_id = ?1)",
                [&candidate],
                |row| row.get(0),
            )?;
            if !exists {
                break candidate;
            }
        };
        let secret = random_admission_secret();
        transaction.execute(
            "INSERT INTO admission_keys (
                key_id, instance_id, request_id, secret, state, created_at
             ) VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
            params![key_id, instance_id, request_id, secret, now],
        )?;
        transaction.commit()?;
        Ok(MintOutcome::New { key_id, secret })
    }

    pub fn acknowledge_admission_keys(
        &self,
        instance_id: &str,
        reported: &[String],
        now: i64,
        overlap_ms: i64,
    ) -> Result<AckResult, AdmissionKeyError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;

        let mut known = std::collections::HashMap::new();
        {
            let mut statement = transaction
                .prepare("SELECT key_id, state FROM admission_keys WHERE instance_id = ?1")?;
            let rows = statement.query_map([instance_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (key_id, state) = row?;
                known.insert(key_id, state);
            }
        }

        for key_id in reported {
            if !known.contains_key(key_id) {
                return Err(AdmissionKeyError::UnknownKey);
            }
        }

        if let Some(active_key) = reported.last() {
            let state = known.get(active_key).expect("validated above");
            if !matches!(state.as_str(), "pending" | "active") {
                return Err(AdmissionKeyError::NotAckable);
            }

            if state == "pending" {
                transaction.execute(
                    "UPDATE admission_keys SET state = 'active', acknowledged_at = ?2
                     WHERE instance_id = ?1 AND key_id = ?3",
                    params![instance_id, now, active_key],
                )?;
            }
            for (key_id, state) in &known {
                if key_id == active_key {
                    continue;
                }
                if state == "active" {
                    transaction.execute(
                        "UPDATE admission_keys
                         SET state = 'retiring', retire_after = COALESCE(retire_after, ?2)
                         WHERE instance_id = ?1 AND key_id = ?3",
                        params![instance_id, now + overlap_ms, key_id],
                    )?;
                }
            }
        }

        let active_key: Option<String> = transaction
            .query_row(
                "SELECT key_id FROM admission_keys
                 WHERE instance_id = ?1 AND state = 'active'
                 ORDER BY acknowledged_at DESC, created_at DESC LIMIT 1",
                [instance_id],
                |row| row.get(0),
            )
            .optional()?;

        let mut retirements = Vec::new();
        {
            let mut statement = transaction.prepare(
                "SELECT key_id, retire_after FROM admission_keys
                 WHERE instance_id = ?1 AND state = 'retiring' AND retire_after IS NOT NULL
                 ORDER BY retire_after, key_id",
            )?;
            let rows = statement.query_map([instance_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                retirements.push(row?);
            }
        }

        transaction.commit()?;
        Ok(AckResult {
            active_key,
            retirements,
        })
    }

    pub fn key_is_active(&self, instance_id: &str, key_id: &str) -> anyhow::Result<bool> {
        let connection = self.lock()?;
        let active: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_keys
             WHERE instance_id = ?1 AND key_id = ?2 AND state = 'active')",
            params![instance_id, key_id],
            |row| row.get(0),
        )?;
        Ok(active)
    }

    pub fn admission_key(
        &self,
        instance_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<AdmissionKeyRecord>> {
        let connection = self.lock()?;
        let record = connection
            .query_row(
                "SELECT key_id, secret, state, retire_after FROM admission_keys
                 WHERE instance_id = ?1 AND key_id = ?2",
                params![instance_id, key_id],
                |row| {
                    Ok(AdmissionKeyRecord {
                        key_id: row.get(0)?,
                        secret: row.get(1)?,
                        state: row.get(2)?,
                        retire_after: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(record)
    }

    pub fn profile_admission_key_id(
        &self,
        instance_id: &str,
        revision: &str,
    ) -> anyhow::Result<Option<String>> {
        let connection = self.lock()?;
        let key_id = connection
            .query_row(
                "SELECT admission_key_id FROM host_profiles
                 WHERE instance_id = ?1 AND revision = ?2",
                params![instance_id, revision],
                |row| row.get(0),
            )
            .optional()?;
        Ok(key_id)
    }

    pub fn expire_admission_keys(&self, now: i64) -> anyhow::Result<usize> {
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE admission_keys SET state = 'retired', secret = ''
             WHERE state = 'retiring' AND retire_after IS NOT NULL AND retire_after <= ?1",
            [now],
        )?;
        Ok(changed)
    }
}

fn random_key_id() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let bytes: [u8; 4] = rand::random();
    bytes
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect()
}

fn random_admission_secret() -> String {
    let bytes: [u8; 32] = rand::random();
    crate::encoding::b64url_encode(&bytes)
}

#[derive(Debug, Clone)]
pub struct ServerListing {
    pub name: String,
    pub protocol: i64,
    pub version: String,
    pub level: String,
    pub players: i64,
    pub max_players: i64,
    pub game_type: i64,
}

#[derive(Debug, Clone)]
pub struct RoutableProfile {
    pub instance_id: String,
    pub profile_json: String,
    pub admission_key_id: String,
    pub secret: String,
}

#[derive(Debug, Clone)]
pub struct ServerIdentityRecord {
    pub private_d: String,
    pub public_jwk: String,
}

impl Store {
    pub fn server_identity(&self, now: i64) -> anyhow::Result<ServerIdentityRecord> {
        let connection = self.lock()?;
        let existing = connection
            .query_row(
                "SELECT private_d, public_jwk FROM provider_identity WHERE id = 1",
                [],
                |row| {
                    Ok(ServerIdentityRecord {
                        private_d: row.get(0)?,
                        public_jwk: row.get(1)?,
                    })
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            return Ok(existing);
        }

        let (public_jwk, private_d) = crate::jwk::generate_keypair()
            .map_err(|error| anyhow::anyhow!("generate provider identity: {error}"))?;
        let public_jwk = serde_json::to_string(&public_jwk)?;
        connection.execute(
            "INSERT OR IGNORE INTO provider_identity (id, private_d, public_jwk, created_at)
             VALUES (1, ?1, ?2, ?3)",
            params![private_d, public_jwk, now],
        )?;
        let record = connection.query_row(
            "SELECT private_d, public_jwk FROM provider_identity WHERE id = 1",
            [],
            |row| {
                Ok(ServerIdentityRecord {
                    private_d: row.get(0)?,
                    public_jwk: row.get(1)?,
                })
            },
        )?;
        Ok(record)
    }

    pub fn listing(&self, now: i64) -> anyhow::Result<Option<ServerListing>> {
        let connection = self.lock()?;
        let listing = connection
            .query_row(
                "SELECT
                    COALESCE(SUM(connected_players), 0),
                    COALESCE(SUM(listing_max_players), 0),
                    MIN(listing_name),
                    MIN(listing_level),
                    MIN(listing_game_type),
                    COALESCE(MIN(listing_protocol), 0),
                    COALESCE(MIN(listing_version), '')
                 FROM leases
                 WHERE routable = 1 AND expires_at > ?1 AND listing_name IS NOT NULL
                 HAVING COUNT(*) > 0",
                [now],
                |row| {
                    Ok(ServerListing {
                        players: row.get(0)?,
                        max_players: row.get(1)?,
                        name: row.get(2)?,
                        level: row.get(3)?,
                        game_type: row.get(4)?,
                        protocol: row.get(5)?,
                        version: row.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(listing)
    }

    pub fn routable_profile(&self, now: i64) -> anyhow::Result<Option<RoutableProfile>> {
        let connection = self.lock()?;
        let profile = connection
            .query_row(
                "SELECT l.instance_id, p.profile_json, p.admission_key_id, k.secret
                 FROM leases l
                 JOIN host_profiles p ON p.revision = l.profile_revision
                 JOIN admission_keys k
                   ON k.instance_id = l.instance_id AND k.key_id = p.admission_key_id
                 WHERE l.routable = 1 AND l.expires_at > ?1 AND k.state = 'active'
                 ORDER BY l.updated_at DESC LIMIT 1",
                [now],
                |row| {
                    Ok(RoutableProfile {
                        instance_id: row.get(0)?,
                        profile_json: row.get(1)?,
                        admission_key_id: row.get(2)?,
                        secret: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(profile)
    }
}
