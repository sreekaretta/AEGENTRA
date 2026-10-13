# AEGENTRA Minimal Test App with Nginx

## Overview

The AEGENTRA Minimal Test App is a Flask application with exactly 10 controlled vulnerabilities, now running behind an Nginx reverse proxy. This setup allows AEGENTRA's execution agent to actually patch infrastructure configurations.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ZAP Scanner                              │
│                  (Scans port 8087)                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Nginx Reverse Proxy                        │
│                   (Port 8087)                                │
│                   Container: aegentra-minimal-nginx          │
│                   Config: nginx.conf (PATCHABLE!)            │
│                                                              │
│   Vulnerabilities:                                            │
│   - Missing security headers                                 │
│   - Server version disclosure                                │
│   - No rate limiting                                         │
│   - No WAF rules                                             │
│   - No SSL/TLS configuration                                 │
│   - Poor error handling                                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Flask Application                          │
│                   (Port 8086)                                │
│                   Container: aegentra-minimal-flask          │
│                                                              │
│   10 Controlled Vulnerabilities:                            │
│   1. SQL Injection (Login)                                   │
│   2. XSS (Reflected) (Search)                                │
│   3. XSS (Stored) (Profile)                                  │
│   4. Insecure Direct Object Reference (Profile)              │
│   5. Arbitrary File Upload (Upload)                          │
│   6. Broken Authentication (Admin)                            │
│   7. CSRF (Password Reset)                                   │
│   8. Information Disclosure (API)                            │
│   9. Directory Traversal (Download)                          │
│   10. Command Injection (Comment)                            │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Start the Application

```bash
cd ~/Aegentra1/minimal-test-app
docker-compose up -d
```

### 2. Verify Services

```bash
# Check if containers are running
docker ps | grep aegentra-minimal

# Test Flask app directly
curl http://localhost:8086

# Test Nginx proxy
curl http://localhost:8087
```

### 3. Run ZAP Scanner

```bash
cd ~/Aegentra1
python3 detection/zap_scanner.py
```

**IMPORTANT**: The scanner will scan port 8087 (Nginx proxy), not port 8086 (Flask app directly).

## Vulnerabilities

### Application-Level Vulnerabilities (Flask)

1. **SQL Injection** - `/login`
   - Vulnerable code: `cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")`
   - CWE: CWE-89
   - Severity: High

2. **XSS (Reflected)** - `/search`
   - Vulnerable code: `return f"Search results for: {query}"`
   - CWE: CWE-79
   - Severity: Medium

3. **XSS (Stored)** - `/profile`
   - Vulnerable code: Stores user input without sanitization
   - CWE: CWE-79
   - Severity: Medium

4. **Insecure Direct Object Reference** - `/profile`
   - Vulnerable code: Accesses user data by ID without authorization
   - CWE: CWE-639
   - Severity: High

5. **Arbitrary File Upload** - `/upload`
   - Vulnerable code: No file type validation
   - CWE: CWE-434
   - Severity: High

6. **Broken Authentication** - `/admin`
   - Vulnerable code: Hardcoded admin credentials
   - CWE: CWE-287
   - Severity: High

7. **CSRF** - `/reset-password`
   - Vulnerable code: No CSRF token
   - CWE: CWE-352
   - Severity: Medium

8. **Information Disclosure** - `/api/data`
   - Vulnerable code: Exposes sensitive data without authentication
   - CWE: CWE-200
   - Severity: Medium

9. **Directory Traversal** - `/download`
   - Vulnerable code: `return send_file(f"uploads/{filename}")`
   - CWE: CWE-22
   - Severity: High

10. **Command Injection** - `/comment`
    - Vulnerable code: `result = os.popen(f"echo {comment}").read()`
    - CWE: CWE-78
    - Severity: High

### Infrastructure-Level Vulnerabilities (Nginx)

1. **Missing Security Headers**
   - Missing: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Content-Security-Policy, Strict-Transport-Security
   - CWE: CWE-693
   - Severity: Medium
   - **PATCHABLE**: AEGENTRA can add these headers to nginx.conf

2. **Server Version Disclosure**
   - Vulnerable code: `server_tokens on;`
   - CWE: CWE-200
   - Severity: Low
   - **PATCHABLE**: AEGENTRA can change to `server_tokens off;`

3. **No Rate Limiting**
   - Missing: rate limiting configuration
   - CWE: CWE-770
   - Severity: Medium
   - **PATCHABLE**: AEGENTRA can add rate limiting rules

4. **No WAF Rules**
   - Missing: ModSecurity rules for SQL injection, XSS, etc.
   - CWE: CWE-693
   - Severity: High
   - **PATCHABLE**: AEGENTRA can add ModSecurity rules

5. **No SSL/TLS Configuration**
   - Missing: HTTPS configuration
   - CWE: CWE-319
   - Severity: High
   - **PATCHABLE**: AEGENTRA can add SSL/TLS configuration

6. **Poor Error Handling**
   - Missing: Custom error pages
   - CWE: CWE-209
   - Severity: Low
   - **PATCHABLE**: AEGENTRA can add proper error handling

## AEGENTRA Patching Capabilities

### What AEGENTRA Can Patch

1. **Security Headers** - Add missing security headers to Nginx config
2. **Server Tokens** - Disable server version disclosure
3. **Rate Limiting** - Add rate limiting rules
4. **WAF Rules** - Add ModSecurity rules for common attacks
5. **SSL/TLS** - Add HTTPS configuration (requires certificates)
6. **Error Handling** - Add custom error pages

### How Patching Works

1. ZAP scanner detects vulnerabilities on port 8087 (Nginx)
2. Alerts are sent to Kafka
3. AEGENTRA agents analyze and create response plans
4. Execution agent patches the Nginx configuration inside the container
5. Nginx is reloaded to apply changes
6. Verification engine confirms patches are applied

### Patching Process

```python
# Execution agent patches Nginx config
1. Detect container: aegentra-minimal-nginx
2. Backup config: docker exec aegentra-minimal-nginx cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
3. Apply patch: docker exec aegentra-minimal-nginx sed -i 's/server_tokens on;/server_tokens off;/' /etc/nginx/nginx.conf
4. Verify syntax: docker exec aegentra-minimal-nginx nginx -t
5. Reload Nginx: docker exec aegentra-minimal-nginx nginx -s reload
6. Verify patch: Check if vulnerability is fixed
```

## Configuration Files

### nginx.conf

The Nginx configuration file is intentionally vulnerable and can be patched by AEGENTRA.

**Location**: `~/Aegentra1/minimal-test-app/nginx.conf`

**Key Sections**:
- `server_tokens on;` - Should be `off`
- Missing security headers in `location /` block
- No rate limiting configuration
- No ModSecurity rules
- No SSL/TLS configuration

### docker-compose.yml

Defines the Flask app and Nginx containers.

**Location**: `~/Aegentra1/minimal-test-app/docker-compose.yml`

**Services**:
- `flask-app`: Flask application on port 8086
- `nginx`: Nginx reverse proxy on port 8087

### config.yaml

AEGENTRA configuration file.

**Location**: `~/Aegentra1/config.yaml`

**Key Settings**:
```yaml
targets:
  minimal_test:
    url: "http://localhost:8087"  # Scan Nginx proxy, not Flask directly
    description: "AEGENTRA Minimal Test Application - Exactly 10 controlled vulnerabilities with Nginx proxy for infrastructure patching"

active_target: "minimal_test"
```

## Testing AEGENTRA

### Complete Workflow

1. **Start all services**
   ```bash
   cd ~/Aegentra1
   bash restart_aegentra.sh
   ```

2. **Start all agents** (7 terminals)
   ```bash
   # Terminal 1
   python3 agents/monitoring/monitoring_agent.py
   
   # Terminal 2
   python3 agents/correlation/correlation_agent.py
   
   # Terminal 3
   python3 agents/analysis/ai_analysis.py
   
   # Terminal 4
   python3 agents/response/universal_response_planning_agent.py
   
   # Terminal 5
   python3 agents/policy_validation/universal_policy_validation_agent.py
   
   # Terminal 6
   python3 agents/execution/real_execution_agent.py
   
   # Terminal 7
   python3 agents/audit/audit_agent.py
   ```

3. **Run ZAP scanner** (Terminal 8)
   ```bash
   python3 detection/zap_scanner.py
   ```

4. **Monitor patching**
   - Check execution agent logs for patching actions
   - Verify Nginx config is modified: `docker exec aegentra-minimal-nginx cat /etc/nginx/nginx.conf`
   - Check if vulnerabilities are fixed

### Expected Results

- **Vulnerabilities Found**: 10 (application-level) + 6 (infrastructure-level) = 16 total
- **Patches Applied**: Security headers, server tokens, rate limiting, WAF rules
- **Automation Time**: < 5 minutes from detection to patching

## Troubleshooting

### Containers Not Starting

```bash
# Check container logs
docker logs aegentra-minimal-flask
docker logs aegentra-minimal-nginx

# Restart containers
cd ~/Aegentra1/minimal-test-app
docker-compose down
docker-compose up -d
```

### Nginx Not Patching

```bash
# Check if execution agent has container access
docker ps | grep aegentra-minimal-nginx

# Check Nginx config
docker exec aegentra-minimal-nginx cat /etc/nginx/nginx.conf

# Check execution agent logs
# Look for errors in the execution agent terminal
```

### Scanner Not Finding Vulnerabilities

```bash
# Verify Nginx is accessible
curl http://localhost:8087

# Check ZAP is running
docker ps | grep zap

# Check ZAP logs
docker logs zap
```

## Cleanup

```bash
# Stop containers
cd ~/Aegentra1/minimal-test-app
docker-compose down

# Remove containers
docker rm aegentra-minimal-flask aegentra-minimal-nginx

# Remove images (optional)
docker rmi aegentra-minimal-flask aegentra-minimal-nginx
```

## Summary

The AEGENTRA Minimal Test App with Nginx provides:
- ✅ Exactly 10 controlled application vulnerabilities
- ✅ 6 infrastructure vulnerabilities that can be patched
- ✅ Real infrastructure patching capabilities
- ✅ Docker-based isolation for safe testing
- ✅ Complete AEGENTRA automation workflow

This setup allows you to test the full AEGENTRA pipeline from vulnerability detection to automated infrastructure patching.
