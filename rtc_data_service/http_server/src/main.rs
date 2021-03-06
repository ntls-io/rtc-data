#![deny(clippy::mem_forget)]
#![feature(toowned_clone_into)]
#![feature(try_blocks)]
#![warn(rust_2018_idioms)]

mod tls;

use std::sync::Arc;

use actix::{Arbiter, Supervisor};
use actix_cors::Cors;
use actix_web::http::header;
use actix_web::web::{self, Data};
use actix_web::{App, HttpServer};
use rtc_data_service::app_config::AppConfig;
use rtc_data_service::auth_enclave_actor::AuthEnclaveActor;
use rtc_data_service::data_enclave_actor::DataEnclaveActor;
use rtc_data_service::data_upload::*;
use rtc_data_service::exec::request_execution;
use rtc_data_service::exec_enclave_actor::ExecEnclaveActor;
use rtc_data_service::exec_token::*;
use rtc_data_service::handlers::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = AppConfig::new().expect("Server config expected");
    let data_enclave_config = Arc::new(config.data_enclave.clone());
    let auth_enclave_config = Arc::new(config.auth_enclave.clone());
    let exec_enclave_config = Arc::new(config.exec_enclave.clone());
    let allowed_origins = config.http_server.allowed_origins;

    let enclave_arbiter = Arbiter::new();

    // Data uses Arc internally, so we don't have to worry about shared ownership
    // see: https://actix.rs/docs/application/
    // Addr might also use Arc internally, so we might have Arc<Arc<_>>. Not sure if this
    // is a big deal atm.
    let data_enclave_addr = Data::new(Supervisor::start_in_arbiter(
        &enclave_arbiter.handle(),
        move |_| DataEnclaveActor::new(data_enclave_config.clone()),
    ));

    let auth_enclave_addr = Data::new(Supervisor::start_in_arbiter(
        &enclave_arbiter.handle(),
        move |_| AuthEnclaveActor::new(auth_enclave_config.clone()),
    ));

    let exec_enclave_addr = Data::new(Supervisor::start_in_arbiter(
        &enclave_arbiter.handle(),
        move |_| ExecEnclaveActor::new(exec_enclave_config.clone()),
    ));

    println!(
        "Starting server at http://{}:{}/",
        config.http_server.host, config.http_server.port
    );

    let server = HttpServer::new(move || {
        let cors = build_cors(&allowed_origins);
        let app = App::new()
            .wrap(cors)
            .app_data(data_enclave_addr.clone())
            .app_data(auth_enclave_addr.clone())
            .app_data(exec_enclave_addr.clone())
            .route("/", web::get().to(server_status))
            .service(auth_enclave_attestation)
            .service(data_enclave_attestation)
            .service(exec_enclave_attestation)
            .service(upload_file)
            .service(req_exec_token)
            .service(request_execution);

        app
    })
    .bind(format!(
        "{}:{}",
        config.http_server.host, config.http_server.port
    ))
    .expect("Failed to bind HTTP server");

    match config.tls {
        Some(tls_conf) => {
            println!(
                "Starting HTTPS server at https://{}:{}/",
                config.http_server.host, config.http_server.port_https
            );
            server
                .bind_rustls(
                    format!(
                        "{}:{}",
                        config.http_server.host, config.http_server.port_https,
                    ),
                    tls::get_tls_server_config(tls_conf).expect("Valid TLS config"),
                )?
                .run()
                .await
        }
        None => server.run().await,
    }
}

fn build_cors(allowed_origins: &Vec<String>) -> Cors {
    match &allowed_origins[..] {
        [allow_any] if allow_any == "*" => {
            println!("WARNING(CORS): All origins are allowed",);
            Cors::default().allow_any_origin()
        }
        [] => {
            println!("WARNING(CORS): No origins are allowed",);
            Cors::default()
        }
        _ => allowed_origins
            .into_iter()
            .fold(Cors::default(), |acc, el| acc.allowed_origin(el.as_ref())),
    }
    .allowed_methods(vec!["GET", "HEAD", "POST", "PUT", "OPTIONS"])
    .allowed_headers(vec![
        header::AUTHORIZATION,
        header::ACCEPT,
        header::CONTENT_TYPE,
    ])
}
