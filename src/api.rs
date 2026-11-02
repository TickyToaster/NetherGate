use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::error::ProviderError;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Store,
}

impl AppState {
    pub fn new(config: Config, store: Store) -> Self {
        Self {
            config: Arc::new(config),
            store,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/.well-known/nethernet-external-signaling", get(discovery))
        .route("/v1/nxs/heartbeat", post(crate::heartbeat::heartbeat))
        .route("/v1/nxs/register", post(crate::registration::register))
        .route("/v1/nxs/complete", post(crate::registration::complete))
        .route("/v1/nxs/{operation}", post(operation))
        .route("/v1/join", get(crate::join::listing))
        .route("/v1/join/{network_id}", post(crate::join::offer))
        .layer(DefaultBodyLimit::max(65_536))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn discovery(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "provider": state.config.public_origin,
        "protocols": ["nethernet-external-signaling-v1"],
        "signatures": ["nxs-es384-v1"],
        "authorization": {
            "schemes": ["anonymous-proof-of-work"]
        },
        "limits": {
            "heartbeatIntervalMs": 5000
        },
        "extensions": {}
    }))
}

async fn operation(Path(operation): Path<String>) -> Result<Json<Value>, ProviderError> {
    match operation.as_str() {
        "register" | "complete" | "heartbeat" | "outcomes" | "rotate" | "retire" | "deregister"
        | "operator-action" => Err(ProviderError::NotImplemented),
        _ => Err(ProviderError::NotFound),
    }
}
