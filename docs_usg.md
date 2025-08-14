# Testing and Usage Guide for Web Application Firewall

## How to Test the Security of the Firewall

### 1. SQL Injection

- Send a request with body containing patterns like `' OR 1=1`, `DROP TABLE`, or `--`.
- Expected result: Response status 403 Forbidden, message: Blocked by firewall: SQL Injection

### 2. Cross-Site Scripting (XSS)

- Send a request with body containing `<script>`, `onerror=`, or `javascript:`.
- Expected result: Response status 403 Forbidden, message: Blocked by firewall: XSS Attack

### 3. Path Traversal

- Send a request with body containing `../` or `..\`.
- Expected result: Response status 403 Forbidden, message: Blocked by firewall: Path Traversal

### 4. Malicious File Uploads

- Send a request with body containing file extensions like `.exe`, `.bat`, `.sh`, `.php`, `.js`, `.jar`, `.py`.
- Expected result: Response status 403 Forbidden, message: Blocked by firewall: Malicious File Upload

### 5. HTTP Header Attacks

- Send a request with headers containing the word `evil` in the key or value.
- Expected result: Response status 403 Forbidden, message: Blocked by firewall: Header Attack

### 6. CSRF Protection

- Send a request without the `x-csrf-token` header or with an empty value.
- Expected result: Response status 403 Forbidden, message: Blocked by firewall: CSRF Attack

### 7. Rate Limiting

- Send multiple requests from the same IP within 1 second.
- Expected result: Response status 403 Forbidden, message: Blocked by firewall: Rate Limit Exceeded

## Function Descriptions

- `contains_sql_injection(input: &str) -> bool`: Checks for common SQL injection patterns in the request body.
- `contains_xss(input: &str) -> bool`: Checks for XSS attack patterns in the request body.
- `contains_path_traversal(input: &str) -> bool`: Detects path traversal attempts in the request body.
- `contains_malicious_file(input: &str) -> bool`: Detects malicious file extensions in the request body.
- `contains_header_attack(headers: &HashMap<&str, &str>) -> bool`: Checks for suspicious header keys or values.
- `valid_csrf(headers: &HashMap<&str, &str>) -> bool`: Ensures the presence of a non-empty CSRF token header.
- `rate_limit(limiter: &Arc<Mutex<HashMap<String, u64>>>, ip: &str) -> bool`: Limits requests per IP to one per second.
- `BlockedRequest(String)`: Custom rejection type for blocked requests, storing the reason.

## Usage

- Start the server with `cargo run`.
- Send HTTP requests to `http://127.0.0.1:8080` using tools like curl, Postman, or a browser.
- Review responses and status codes to verify firewall protections.
