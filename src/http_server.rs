use anyhow::Error;
use warp::Filter;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use rcgen::generate_simple_self_signed;
use tokio::task;
use crate::plesk_api::PleskAPI;
use crate::settings::Settings;


#[derive(Debug, Deserialize)]
struct DnsAddRequest {
    pub value: String,
}
#[derive(Debug, Deserialize)]
struct DnsRemovalRequest {
    pub record_id: String,
}

#[derive(Debug, Serialize)]
struct DnsResponse {
    pub status: String,
    pub record_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct SolverResponse {
    pub solver: String
}

pub struct HttpServer {
    plesk_api: Arc<PleskAPI>,
    group_name: String,
    solver_name: String,
    solver_version: String,
}

impl HttpServer {
    pub fn new(settings: &Settings) -> Self {
        let plesk_api = PleskAPI::new(
            settings.plesk.url.clone(),
            settings.plesk.siteid.clone(),
            settings.plesk.username.clone(),
            settings.plesk.password.clone(),
        );
        HttpServer {
            plesk_api: Arc::new(plesk_api),
            group_name: settings.common.groupname.clone(),
            solver_name: settings.common.solvername.clone(),
            solver_version: settings.common.solverversion.clone()
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {

        let plesk_api_clone_cleanup = self.plesk_api.clone();
        let plesk_api_clone_present = self.plesk_api.clone();
        let solver_name = self.solver_name.clone();
        
        let present_route = warp::path("present")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |body| {
            let plesk_api = plesk_api_clone_present.clone();
            handle_present(body, plesk_api)
        });

        let cleanup_route = warp::path("cleanup")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |body| {
                let plesk_api = plesk_api_clone_cleanup.clone();
                handle_cleanup(body, plesk_api)
        });

        let solver_route = warp::path("apis")
            .and(warp::path(self.group_name.clone()))
            .and(warp::path(self.solver_version.clone()))
            .and(warp::get())
            .and_then(move || {
                handle_solver(solver_name.clone())
            });

        // Combine the routes
        let routes = present_route.or(cleanup_route).or(solver_route)
            .with(warp::log::custom(|info| {
                tracing::info!(
                    "Request: {} {} from {}",
                    info.method(),
                    info.path(),
                    info.remote_addr().map(|addr| addr.to_string()).unwrap_or_else(|| "unknown".to_string())
                );
            }));

        // SAN; todo make this configurable
        let subject_alt_names = vec![
            "localhost".into(),
            format!("{}.cert-manager.svc.cluster.local", self.solver_name),
        ];
        // Generate an in-memory self-signed certificate
        let cert_key = generate_simple_self_signed(subject_alt_names)?;

        // Serialize the certificate and the private key to PEM format
        let priv_key_pem = cert_key.key_pair.serialize_pem();
        let cert_pem = cert_key.cert.pem();


        // Clone the routes for both HTTP and HTTPS
        let routes_http = routes.clone();
        let routes_https = routes;

        // Serve non-TLS on port 8000
        let http_server = task::spawn(async move {
            warp::serve(routes_http)
                .run(([0, 0, 0, 0], 8080))
                .await;
        });

        // Serve TLS on port 443
        let https_server = task::spawn(async move {
            warp::serve(routes_https)
                .tls()
                .key(priv_key_pem.as_bytes())
                .cert(cert_pem.as_bytes())
                .run(([0, 0, 0, 0], 8443))
                .await;
        });

        // Run both servers concurrently
        tokio::try_join!(http_server, https_server)?;

        Ok(())
    }   
}

async fn handle_present(body: DnsAddRequest, plesk_api: Arc<PleskAPI>) -> Result<impl warp::Reply, warp::Rejection> {
    let value = body.value;

    info!("Received /present request for Value: {}", value);
    
    let result = plesk_api.add_challenge(value).await;

    // Respond with a success message
    if result.is_err() {
        let response = DnsResponse {
            status: "error".to_string(),
            record_id: None,
        };
        return Ok(warp::reply::json(&response));
    }
    let response = DnsResponse {
        status: "success".to_string(),
        record_id: result.ok(),
    };
    Ok(warp::reply::json(&response))
}

// Handler for the /cleanup endpoint
async fn handle_cleanup(body: DnsRemovalRequest, plesk_api: Arc<PleskAPI>) -> Result<impl warp::Reply, warp::Rejection> {
    // Extract the FQDN and value from the request body
    let record_id = body.record_id;

    info!("Received /cleanup request for Record ID: {}", record_id);
    let result = plesk_api.remove_challenge(record_id).await;

    if result.is_err() {
        let response = DnsResponse {
            status: "error".to_string(),
            record_id: None,
        };
        return Ok(warp::reply::json(&response));
    }

    // Respond with a success message
    let response = DnsResponse {
        status: "success".to_string(),
        record_id: None,
    };
    Ok(warp::reply::json(&response))
}

async fn handle_solver(solver_name: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&SolverResponse {
        solver: solver_name,
    }))
}
