use anyhow::Error;
use warp::Filter;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
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

pub struct HttpServer {
    plesk_api: Arc<PleskAPI>,
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
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {

        let plesk_api_clone_cleanup = self.plesk_api.clone();
        let plesk_api_clone_present = self.plesk_api.clone();
        
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

        // Combine the routes
        let routes = present_route.or(cleanup_route)
            .with(warp::log::custom(|info| {
                tracing::info!(
                    "Request: {} {} from {}",
                    info.method(),
                    info.path(),
                    info.remote_addr().map(|addr| addr.to_string()).unwrap_or_else(|| "unknown".to_string())
                );
            }));

        // Start the warp server
        warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;

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
