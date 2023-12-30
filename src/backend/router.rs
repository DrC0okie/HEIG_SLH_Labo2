use axum::error_handling::HandleErrorLayer;
use axum::middleware::from_extractor;
use axum::{BoxError, Router};
use axum::routing::{get, post};
use http::StatusCode;
use log::{debug, info, trace, warn};
use tower_http::cors;
use tower_http::cors::{AllowMethods, CorsLayer};
use tower_sessions::{SessionManagerLayer, MemoryStore};
use crate::backend::middlewares::{AccessUser, RefreshUser};

pub fn get_router() -> Router {
    trace!("Init main router");

    // CORS allow requests from any source ONLY in debug mode
    let router = if cfg!(debug_assertions) {
        info!("Allow CORS from any");
        let cors = CorsLayer::new()
            .allow_methods(AllowMethods::any())
            .allow_origin(cors::Any);
        Router::new().layer(cors)
    } else {
        Router::new()
    };

    // Session manager layer
    let store = MemoryStore::default();
    let manager = SessionManagerLayer::new(store).with_http_only(true);
    let service = tower::ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|e: BoxError| async move {
            warn!("Session manager catched an error");
            debug!("Error catched : {e}");
            StatusCode::BAD_REQUEST
        }))
        .layer(manager);

    router
        .merge(unauth())
        .merge(access())
        .merge(refresh())
        .layer(service)
}

fn unauth() -> Router {
    use crate::backend::handlers_unauth::*;

    trace!("Init router without auth");

    Router::new()
        .route("/", get(home))
        .route("/email/:email", get(email))
        .route("/register", post(register))
        .route("/verify/:token", get(verify))
        .route("/login", get(login_page))
        .route("/login", post(login))
        .route("/logout", get(logout))
}

fn access() -> Router {
    use crate::backend::handlers_access::*;

    trace!("Init router for access JWT");

    Router::new()
        .route("/change-password", post(change_password))
        .layer(from_extractor::<AccessUser>()) // Middleware checking for access JWT
}

fn refresh() -> Router {
    use crate::backend::handlers_refresh::*;

    trace!("Init router for refresh JWT");

    Router::new()
        .route("/get-access", get(get_access))
        .layer(from_extractor::<RefreshUser>()) // Middleware checking for refresh JWT
}
