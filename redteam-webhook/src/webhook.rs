use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

use crate::{AppState, db, github::PullRequestEvent};

type HmacSha256 = Hmac<Sha256>;

pub fn router() -> Router<AppState> {
    Router::new().route("/webhook/github", post(handle_github_webhook))
}

async fn handle_github_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // Verify HMAC-SHA256 signature
    let sig_header = match headers.get("x-hub-signature-256") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => {
                warn!("Invalid x-hub-signature-256 header encoding");
                return StatusCode::BAD_REQUEST;
            }
        },
        None => {
            warn!("Missing x-hub-signature-256 header");
            return StatusCode::UNAUTHORIZED;
        }
    };

    if !verify_signature(&state.webhook_secret, &body, &sig_header) {
        warn!("Webhook signature verification failed");
        return StatusCode::UNAUTHORIZED;
    }

    let event_type = match headers.get("x-github-event") {
        Some(v) => v.to_str().unwrap_or("unknown").to_owned(),
        None => {
            warn!("Missing x-github-event header");
            return StatusCode::BAD_REQUEST;
        }
    };

    if event_type != "pull_request" {
        return StatusCode::OK; // Ignore non-PR events
    }

    let payload: PullRequestEvent = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse PR payload: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Only scan opened/synchronize/reopened events
    if !matches!(payload.action.as_str(), "opened" | "synchronize" | "reopened") {
        return StatusCode::OK;
    }

    info!(
        "Received PR #{} ({}) for {}/{}",
        payload.pull_request.number,
        payload.action,
        payload.repository.full_name,
        payload.pull_request.head.sha,
    );

    let scan_id = match db::create_scan(
        &state.pool,
        &payload.repository.clone_url,
        &payload.pull_request.head.sha,
        &payload.repository.full_name,
        payload.pull_request.number,
    ).await {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to create scan record: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Fire-and-forget: POST to Python agent
    let agent_url = state.agent_url.clone();
    let clone_url = payload.repository.clone_url.clone();
    let sha = payload.pull_request.head.sha.clone();
    tokio::spawn(async move {
        trigger_agent_scan(&agent_url, scan_id, &clone_url, &sha).await;
    });

    StatusCode::ACCEPTED
}

fn verify_signature(secret: &str, body: &[u8], sig_header: &str) -> bool {
    let expected_hex = sig_header.strip_prefix("sha256=").unwrap_or("");
    let expected_bytes = match hex::decode(expected_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let computed = mac.finalize().into_bytes();

    computed.as_slice().ct_eq(&expected_bytes).into()
}

async fn trigger_agent_scan(
    agent_url: &str,
    scan_id: uuid::Uuid,
    clone_url: &str,
    sha: &str,
) {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "scan_id": scan_id,
        "clone_url": clone_url,
        "sha": sha,
    });
    let url = format!("{agent_url}/internal/scan");
    match client.post(&url).json(&payload).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!("Agent scan triggered for scan_id={scan_id}");
        }
        Ok(resp) => {
            error!("Agent returned {} for scan_id={scan_id}", resp.status());
        }
        Err(e) => {
            error!("Failed to contact agent for scan_id={scan_id}: {e}");
        }
    }
}
