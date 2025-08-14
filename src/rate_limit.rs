use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn rate_limit(limiter: &Arc<Mutex<HashMap<String, Vec<u64>>>>, ip: &str) -> bool {
    let mut map = limiter.lock().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let window = 10;
    let max_requests = 5;
    let entry = map.entry(ip.to_string()).or_insert_with(Vec::new);
    entry.retain(|&t| now - t < window);
    if entry.len() >= max_requests {
        false
    } else {
        entry.push(now);
        true
    }
}
