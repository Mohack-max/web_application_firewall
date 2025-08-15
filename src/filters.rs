use regex::Regex;
use std::collections::HashMap;
use warp::http::HeaderMap;

pub fn contains_sql_injection(input: &str) -> bool {
    let patterns = [
        r"(?i)(\bor\b|\band\b).*(=|like)",
        r"(?i)union.*select",
        r"(?i)select.*from",
        r"(?i)insert\s+into",
        r"(?i)drop\s+table",
        r"(?i)--",
        r"(?i)/\*.*\*/",
        r"(?i);"
    ];
    patterns.iter().any(|pat| Regex::new(pat).unwrap().is_match(input))
}

pub fn contains_xss(input: &str) -> bool {
    let patterns = [
        r"(?i)<script.*?>.*?</script>",
        r"(?i)onerror=",
        r"(?i)onload=",
        r"(?i)<img.*?>",
        r"(?i)<svg.*?>",
        r"(?i)javascript:"
    ];
    patterns.iter().any(|pat| Regex::new(pat).unwrap().is_match(input))
}

pub fn contains_path_traversal(input: &str) -> bool {
    let patterns = [r"\.\./", r"\.\.\\"];
    patterns.iter().any(|pat| Regex::new(pat).unwrap().is_match(input))
}

pub fn contains_malicious_file(input: &str) -> bool {
    
    let patterns = [r"\.exe$", r"\.bat$", r"\.sh$", r"\.php$", r"\.js$", r"\.jar$", r"\.py$", r"\.com$", r"\.scr$", r"\.msi$", r"\.vbs$", r"\.ps1$"];
    patterns.iter().any(|pat| Regex::new(pat).unwrap().is_match(input))
}

pub fn contains_malicious_file_bytes(bytes: &[u8]) -> bool {
    
    bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7FELF") || bytes.starts_with(b"#!/bin/bash") || bytes.starts_with(b"#!/usr/bin/env python")
}

pub fn contains_header_attack(headers: &HashMap<&str, &str>) -> bool {
    let forbidden_headers = ["evil", "attack", "malicious", "script"];
    headers.iter().any(|(k, v)| forbidden_headers.iter().any(|f| k.contains(f) || v.contains(f)))
}

pub fn valid_csrf(headers_map: &HashMap<&str, &str>, headers: &HeaderMap) -> bool {
    let csrf_token = headers_map.get("x-csrf-token").map_or("", |v| *v);
    let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
    let referer = headers.get("referer").and_then(|v| v.to_str().ok()).unwrap_or("");
    !csrf_token.is_empty() && (origin.starts_with("https://yourdomain.com") || referer.starts_with("https://yourdomain.com"))
}

pub fn valid_csrf_dev(_headers_map: &HashMap<&str, &str>, _headers: &HeaderMap) -> bool {
    true
}
