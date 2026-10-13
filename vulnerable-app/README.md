# AEGENTRA Vulnerable Test Application

A deliberately vulnerable web application designed for testing the AEGENTRA security automation platform. This application contains 20+ known vulnerabilities across different categories to provide a controlled environment for testing security automation effectiveness.

## 🚨 WARNING

This application is intentionally vulnerable and should **ONLY** be used for:
- Security testing and research
- Educational purposes
- Testing security automation tools
- Penetration testing practice

**NEVER** deploy this application in production environments or expose it to the internet.

## 🐛 Vulnerabilities Included

### 1. SQL Injection (Multiple Points)
- **Login Form**: `' OR '1'='1`
- **Search Function**: `' UNION SELECT * FROM users--`
- **Product Details**: `1' OR '1'='1`
- **Blind SQL Injection**: `' AND (SELECT COUNT(*) FROM users) > 0--`

### 2. Cross-Site Scripting (XSS)
- **Stored XSS**: Comments section
- **Reflected XSS**: Search results
- **DOM-based XSS**: Product details

### 3. Authentication & Authorization Issues
- **Weak Password Storage**: MD5 hashing without salt
- **Authorization Bypass**: Any user can access admin panel
- **Insecure Direct Object Reference**: Access any user's profile
- **Predictable Password Reset Tokens**: Base64 encoded emails

### 4. File Upload Vulnerabilities
- **Unrestricted File Upload**: No file type validation
- **Path Traversal**: `../../../etc/passwd`
- **Missing Virus Scanning**: No malware detection

### 5. Information Disclosure
- **Debug Information**: `/debug` endpoint exposes environment variables
- **Configuration Exposure**: `/config` endpoint shows hardcoded credentials
- **Password Hashes**: Exposed in admin panel
- **Search Logs**: User queries logged without sanitization

### 6. Session Management Issues
- **Weak Session Management**: Predictable session IDs
- **No CSRF Protection**: Forms lack CSRF tokens
- **Insecure Secret Key**: Hardcoded in application

### 7. Input Validation Issues
- **No Input Sanitization**: User input stored/processed as-is
- **Missing Rate Limiting**: No protection against brute force
- **No Output Encoding**: XSS vulnerabilities

## 🚀 Quick Start

### Using Docker (Recommended)

1. **Build and run with Docker Compose:**
   ```bash
   cd vulnerable-app
   docker-compose up -d
   ```

2. **Access the application:**
   - URL: http://localhost:8085
   - Database: Persistent in `./database/`
   - Uploads: Stored in `./uploads/`

### Manual Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python app.py
   ```

3. **Access the application:**
   - URL: http://localhost:8085

## 📋 Test Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | password123 | admin |
| user1 | 123456 | user |
| test | test | user |
| guest | guest | guest |

## 🧪 Testing Scenarios

### SQL Injection Tests
```bash
# Login bypass
Username: ' OR '1'='1
Password: anything

# Search injection
Search: ' UNION SELECT id,username,password,email,role,profile FROM users--

# Product details injection
URL: /product/1' OR '1'='1
```

### XSS Tests
```html
<!-- Stored XSS in comments -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

### Authorization Tests
```bash
# Access admin panel as any user
GET /admin

# Access other user profiles
GET /profile?id=1
GET /profile?id=2
```

### File Upload Tests
```bash
# Upload malicious files
- PHP web shell: shell.php
- HTML with JS: malicious.html
- Executable: malware.exe
```

### Path Traversal Tests
```bash
# Access system files
GET /uploads/../../../etc/passwd
GET /uploads/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
```

## 🔧 Integration with AEGENTRA

1. **Add to AEGENTRA targets:**
   ```yaml
   targets:
     aegentra_test:
       url: "http://localhost:8085"
       description: "AEGENTRA Vulnerable Test Application"
   active_target: "aegentra_test"
   ```

2. **Run AEGENTRA scan:**
   ```bash
   python detection/zap_scanner.py
   ```

3. **Monitor the 8-stage pipeline:**
   - Detection → Unified → Incidents → Analysis → Plans → Decisions → Execution → Audit

## 📊 Expected Results

### First Scan (Baseline)
- **SQL Injection**: 5+ instances
- **XSS**: 8+ instances  
- **Authentication Issues**: 4+ instances
- **File Upload Issues**: 3+ instances
- **Information Disclosure**: 6+ instances

### After Automation
- **Headers Added**: Security headers should be present
- **WAF Rules**: SQL injection attempts blocked
- **Rate Limiting**: Brute force attempts throttled
- **URL Quarantine**: Vulnerable endpoints restricted

## 🛠️ Vulnerability Details

### 1. SQL Injection in Login
**Location**: `/login` (POST)
**Vulnerable Code**:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```
**Payload**: `' OR '1'='1`

### 2. Stored XSS in Comments
**Location**: `/comment` (POST)
**Vulnerable Code**:
```python
<p>{{ comment.comment|safe }}</p>
```
**Payload**: `<script>alert(1)</script>`

### 3. Authorization Bypass
**Location**: `/admin`
**Vulnerable Code**:
```python
if 'user_id' not in session:
    return redirect(url_for('login'))
# Missing role check!
```

### 4. Unrestricted File Upload
**Location**: `/upload` (POST)
**Vulnerable Code**:
```python
filename = file.filename
file.save(os.path.join('uploads', filename))
```

## 🔍 Testing Your Security Automation

### Step 1: Baseline Scan
1. Start the vulnerable application
2. Run AEGENTRA with `active_target: "aegentra_test"`
3. Record all detected vulnerabilities
4. Note the severity and confidence scores

### Step 2: Apply Automation
1. Let AEGENTRA execute automated fixes
2. Monitor the policy validation decisions
3. Track which actions are approved vs held for review
4. Review the execution results

### Step 3: Verification Scan
1. Scan the application again
2. Compare results with baseline
3. Verify that vulnerabilities are actually fixed
4. Check for any regressions

### Step 4: State Persistence Test
1. Restart the vulnerable application
2. Verify that fixes persist
3. Test that the application remains functional
4. Confirm no new vulnerabilities introduced

## 📝 Customization

### Adding New Vulnerabilities
1. Add new routes in `app.py`
2. Create corresponding templates
3. Update documentation
4. Test with AEGENTRA

### Modifying Existing Vulnerabilities
1. Edit the vulnerable code patterns
2. Update test cases
3. Re-run AEGENTRA scans
4. Verify detection accuracy

## 🤝 Contributing

When adding new vulnerabilities:
1. Follow the existing code patterns
2. Add comprehensive test cases
3. Update this documentation
4. Test with AEGENTRA pipeline

## ⚖️ Legal Notice

This application is provided for educational and testing purposes only. Users are responsible for:
- Ensuring proper isolation from production networks
- Complying with applicable laws and regulations
- Not using for malicious purposes
- Securing the testing environment

## 📞 Support

For issues related to:
- **AEGENTRA Integration**: Check main project documentation
- **Vulnerability Details**: Review the source code comments
- **Docker Issues**: Verify Docker and Docker Compose versions
- **Network Issues**: Check port availability and firewall settings

---

**Remember**: This is a controlled testing environment. Always ensure proper security measures when running vulnerable applications!