//Rien besoin de changer ici

mod backend;
mod database;
mod utils;
mod email;
mod consts;

use std::net::SocketAddr;
use handlebars::Handlebars;
use log::info;
use once_cell::sync::Lazy;
use crate::consts::HTTP_PORT;

static HBS: Lazy<Handlebars> = Lazy::new(|| {
    info!("Init handlebar");
    let mut hbs = Handlebars::new();
    hbs.register_templates_directory(".hbs", "templates/")
        .expect("Could not register template directory");
    hbs
});

#[tokio::main]
async fn main() {

    dotenv::dotenv().ok();

    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    // Reload DB from files
    database::user::load().ok();
    database::token::load().ok();
    database::email::load().ok();

    // Setup the endpoints
    let app = backend::router::get_router();

    // Start web server
    let addr = SocketAddr::from(([0, 0, 0, 0], HTTP_PORT));
    info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to open web server listener");

    info!("Start Axum listener");
    axum::serve(listener, app)
        .await
        .expect("Failed to bind Axum to listener");
}
