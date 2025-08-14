mod filters;
mod rate_limit;
mod types;

use warp::Filter;
use std::sync::{Arc, Mutex};
use bytes::Bytes;
use bytes::Buf;
use std::collections::HashMap;
use filters::*;
use rate_limit::rate_limit;
use types::BlockedRequest;
use warp::http::Method;
use warp::multipart::{FormData};
use futures::stream::TryStreamExt;

async fn handle_multipart(form: FormData, headers: warp::http::HeaderMap, addr: Option<std::net::SocketAddr>, rate_limiter: Arc<Mutex<HashMap<String, Vec<u64>>>>) -> Result<impl warp::Reply, warp::Rejection> {
    let ip = addr.map(|a| a.ip().to_string()).unwrap_or_default();
    let mut file_name = String::new();
    let mut file_bytes = Vec::new();
    let mut body_str = String::new();
    let headers_map = headers.iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or(""))).collect::<HashMap<_, _>>();
    let mut parts = form;
    while let Some(part) = parts.try_next().await.unwrap_or(None) {
        if part.name() == "file" {
            if let Some(filename) = part.filename() {
                file_name = filename.to_string();
            }
            let data = part.stream().try_fold(Vec::new(), |mut acc, mut chunk| async move {
                acc.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
                Ok(acc)
            }).await.unwrap_or_default();
            file_bytes = data;
        } else {
            let value = part.stream().try_fold(Vec::new(), |mut acc, mut chunk| async move {
                acc.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
                Ok(acc)
            }).await.unwrap_or_default();
            body_str = String::from_utf8_lossy(&value).to_string();
        }
    }
    let reason = if contains_malicious_file(&file_name) || contains_malicious_file_bytes(&file_bytes) {
        Some("Malicious File Upload")
    } else if !rate_limit(&rate_limiter, &ip) {
        Some("Rate Limit Exceeded")
    } else {
        None
    };
    match reason {
        Some(r) => Err(warp::reject::custom(BlockedRequest(r.into()))),
        None => Ok(warp::reply::with_status("File upload accepted", warp::http::StatusCode::OK)),
    }
}

#[tokio::main]
async fn main() {
    let rate_limiter = Arc::new(Mutex::new(HashMap::<String, Vec<u64>>::new()));
    let rate_limiter_filter = warp::any().map(move || rate_limiter.clone());
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(&[Method::POST])
        .allow_headers(vec!["content-type", "evil", "x-csrf-token"]);


    let filters = warp::any()
        .and(warp::body::bytes())
        .and(warp::header::headers_cloned())
        .and(warp::addr::remote())
        .and(rate_limiter_filter.clone())
        .and_then(|body: Bytes, headers: warp::http::HeaderMap, addr: Option<std::net::SocketAddr>, rate_limiter| {
            let ip = addr.map(|a| a.ip().to_string()).unwrap_or_default();
            let body_str = String::from_utf8_lossy(&body);
            let headers_map = headers.iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or(""))).collect::<HashMap<_, _>>();
            let reason = if contains_header_attack(&headers_map) {
                Some("Header Attack")
            } else if !valid_csrf_dev(&headers_map, &headers) {
                Some("CSRF Attack")
            } else if !rate_limit(&rate_limiter, &ip) {
                Some("Rate Limit Exceeded")
            } else if contains_sql_injection(&body_str) {
                Some("SQL Injection")
            } else if contains_xss(&body_str) {
                Some("XSS Attack")
            } else if contains_path_traversal(&body_str) {
                Some("Path Traversal")
            } else {
                None
            };
            Box::pin(async move {
                match reason {
                    Some(r) => Err(warp::reject::custom(BlockedRequest(r.into()))),
                    None => Ok("Web Application Firewall Running"),
                }
            })
        });

    
    let upload = warp::path("upload")
        .and(warp::multipart::form())
        .and(warp::header::headers_cloned())
        .and(warp::addr::remote())
        .and(rate_limiter_filter)
        .and_then(|mut form: warp::multipart::FormData, headers: warp::http::HeaderMap, addr: Option<std::net::SocketAddr>, rate_limiter| async move {
            let ip = addr.map(|a| a.ip().to_string()).unwrap_or_default();
            let mut reason = None;
            let mut file_name = String::new();
            let mut file_bytes = Vec::new();
            while let Some(part) = form.try_next().await.unwrap_or(None) {
                if part.name() == "file" {
                    file_name = part.filename().unwrap_or("").to_string();
                    file_bytes = part.stream()
                        .try_fold(Vec::new(), |mut acc, mut chunk| async move {
                            acc.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
                            Ok(acc)
                        })
                        .await
                        .unwrap_or_default();
                }
            }    
            if contains_malicious_file(&file_name) || contains_malicious_file_bytes(&file_bytes) {
                reason = Some("Malicious File Upload");
            } else if !rate_limit(&rate_limiter, &ip) {
                reason = Some("Rate Limit Exceeded");
            }
            match reason {
                Some(r) => Err(warp::reject::custom(BlockedRequest(r.into()))),
                None => Ok("File upload passed WAF checks"),
            }
        });

    let route = filters
        .or(upload)
        .recover(|err: warp::Rejection| async move {
            if let Some(blocked) = err.find::<BlockedRequest>() {
                let reply = warp::reply::with_status(
                    format!("Blocked by firewall: {}", blocked.0),
                    warp::http::StatusCode::FORBIDDEN,
                );
                Ok(warp::reply::with_header(reply, "Access-Control-Allow-Origin", "*"))
            } else {
                Err(err)
            }
        })
        .with(cors);
    warp::serve(route).run(([127, 0, 0, 1], 8080)).await;
}
