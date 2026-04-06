mod db;
mod github;
mod webhook;

use anyhow::Context;
use axum::{Router, routing::get};
use sqlx::postgres::PgPoolOptions;
use std::env;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub webhook_secret: String,
    pub agent_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "vulnchain_webhook=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = env::var("DATABASE_URL")
        .context("DATABASE_URL must be set")?;
    let webhook_secret = env::var("GITHUB_WEBHOOK_SECRET")
        .context("GITHUB_WEBHOOK_SECRET must be set")?;
    let agent_url = env::var("AGENT_URL")
        .unwrap_or_else(|_| "http://agent:8080".to_string());
    let port: u16 = env::var("WEBHOOK_PORT")
        .unwrap_or_else(|_| "9000".to_string())
        .parse()
        .context("WEBHOOK_PORT must be a valid port number")?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to PostgreSQL")?;

    db::run_migrations(&pool).await?;

    let state = AppState { pool, webhook_secret, agent_url };

    let app = Router::new()
        .route("/health", get(health))
        .merge(webhook::router())
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr = format!("0.0.0.0:{port}");
    info!("vulnchain-webhook listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}
