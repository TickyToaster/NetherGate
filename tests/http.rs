use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use nxsd::api::{AppState, router};
use nxsd::config::Config;
use nxsd::store::Store;
use tower::ServiceExt;

fn app() -> Router {
    let store = Store::open_in_memory().expect("in-memory store");
    store.migrate().expect("migrations");
    router(AppState::new(Config::default(), store))
}

async fn send(request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app().oneshot(request).await.expect("request succeeds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn healthz_is_ok() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn discovery_reports_configured_provider() {
    let (status, body) = send(
        Request::builder()
            .uri("/.well-known/nethernet-external-signaling")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["provider"], "http://localhost:8080");
    assert_eq!(body["protocols"][0], "nethernet-external-signaling-v1");
    assert_eq!(body["signatures"][0], "nxs-es384-v1");
}

#[tokio::test]
async fn known_operations_are_explicitly_unimplemented() {
    let (status, body) = send(
        Request::builder()
            .method("POST")
            .uri("/v1/nxs/outcomes")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["code"], "not_implemented");
}

#[tokio::test]
async fn unknown_operations_are_not_found() {
    let (status, body) = send(
        Request::builder()
            .method("POST")
            .uri("/v1/nxs/unknown")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
}

#[tokio::test]
async fn join_offer_requires_a_network_id() {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/join")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn malformed_json_returns_spec_error_not_axum_422() {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/nxs/register")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json error body");
    assert_eq!(body["code"], "invalid_request");
}
