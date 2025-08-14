# Web Application Firewall Coding Process Documentation

This file documents the coding process for building a web application firewall in Rust using the `warp` framework. No comments are included in the codebase itself.

## Dependency Descriptions

- **warp**: A fast, flexible, and lightweight web framework for Rust. Used to build HTTP servers and handle routing, request filtering, and responses.
- **tokio**: An asynchronous runtime for Rust. Required by `warp` to handle async operations, such as serving HTTP requests concurrently and efficiently.
- **bytes**: Utilities for working with byte buffers, used for request/response bodies and file uploads.
- **regex**: Regular expressions for attack detection (SQLi, XSS, path traversal, etc.).
- **futures**: Provides combinators and utilities for working with async streams, used for multipart file handling.

## Steps Completed

1. Initialized Rust project and verified Cargo setup.
2. Added `warp` dependency to `Cargo.toml` for HTTP server functionality.
3. Added `tokio` dependency for async runtime support.
4. Implemented a basic HTTP server in `main.rs` that responds to any request with a simple message.

## Request Filtering Logic

A request filter was added to block any HTTP request containing the header `x-blocked`. If this header is present, the server responds with a 403 Forbidden status and the message "Blocked by firewall". Otherwise, the request is allowed and receives the default response.

This demonstrates how the firewall can inspect and control incoming requests based on custom rules. The filtering logic can be extended to check for other headers, paths, or request properties as needed.

## Advanced Protection: SQL Injection

A modular filter system was introduced to inspect HTTP request bodies for SQL injection patterns. The firewall checks for common SQL injection signatures (such as "' OR 1=1", "--", "DROP TABLE", etc.) in incoming requests. If a pattern is detected, the request is blocked and a 403 Forbidden response is returned with the message "Blocked by firewall: SQL Injection detected".

This approach can be extended to detect other attack types by adding more filters and pattern checks.

## Next Steps

- Add logging and monitoring features.
- Expand documentation as new features are added.

All code changes are tracked in the codebase, while explanations and decisions are documented here.
