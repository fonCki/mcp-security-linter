# Security Analyzers

## 1. Command Injection Detection

Detects dangerous command execution patterns that could lead to arbitrary code execution.

### Patterns Detected
- Direct exec/execSync usage with user input
- Subprocess calls with shell=true
- Dangerous commands (rm -rf, curl | bash, etc.)
- Base64 encoded PowerShell execution

## 2. Token Passthrough

Identifies anti-patterns where client Authorization headers are forwarded to downstream services.

### Patterns Detected
- Forwarding req.headers.authorization directly
- Copying all headers without filtering
- Missing server-to-server authentication

## 3. Unauthenticated Endpoints

Finds HTTP/WebSocket endpoints without proper authentication.

### Patterns Detected
- Express routes without auth middleware
- WebSocket connections without verification
- Public endpoints exposing sensitive operations

## 4. OAuth Hygiene

Checks OAuth implementation for common security issues.

### Patterns Detected
- Missing state parameter generation
- No state verification on callback
- Missing redirect_uri validation
- Overly permissive CORS settings

## 5. Argument Validation

Detects usage of unvalidated tool arguments in MCP handlers.

### Patterns Detected
- Direct usage of args.* without validation
- Missing schema definitions
- No input sanitization