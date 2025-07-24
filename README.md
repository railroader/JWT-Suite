# JWT Manager - Burp Suite Extension

![JWT Manager](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Java](https://img.shields.io/badge/Java-17+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.0.0-red)

A comprehensive Burp Suite extension for JSON Web Token (JWT) security testing, analysis, and automated session management. This extension provides a complete toolkit for security professionals to analyze, manipulate, and attack JWT implementations with an intuitive interface and powerful automation capabilities.

## 🚀 Key Features

### 🔍 **JWT Analysis & Decoding**
- **Automatic JWT Detection**: Finds JWT tokens in headers, cookies, request/response bodies
- **Comprehensive Decoding**: Complete JWT structure analysis with tabbed interface
- **Security Analysis**: Professional-grade vulnerability detection and risk assessment
- **Multiple Token Support**: Handles multiple JWTs in single requests
- **Smart Validation**: Verifies JWT structure and format integrity

### ⚔️ **Attack Tools**
- **None Algorithm Attack**: Tests for unsigned token acceptance vulnerabilities
- **Algorithm Confusion**: Exploits RSA-to-HMAC and other algorithm confusion attacks
- **Signature Bypass**: Tests various signature manipulation techniques
- **CVE Detection**: Identifies known vulnerabilities (CVE-2022-21449 Psychic Signatures)
- **Weak Secret Testing**: Automated brute force with common weak secrets

### 🔨 **Brute Force Engine**
- **JWT Signing Key Cracking**: High-performance HMAC secret discovery
- **Custom Wordlists**: Support for custom wordlist files
- **Real-time Progress**: Live attack progress monitoring with ETA
- **Result Analysis**: Detailed reporting of successful key discoveries
- **Multi-algorithm Support**: Works with HS256, HS384, HS512 algorithms

### 🔄 **Session Management**
- **Reactive JWT Vault System**: Intelligent JWT storage and injection
- **401 Response Handling**: Automatic re-authentication on token expiration
- **API Calls Monitoring**: Real-time tracking of all JWT-protected requests
- **Configurable Authentication**: Flexible auth endpoint configuration
- **Scope-Aware**: Only processes requests within Burp's configured scope

### 🎯 **Context Menu Integration**
- **One-Click Analysis**: Right-click integration in Proxy, Repeater, Target, Logger
- **Send to JWT Tools**: Direct request forwarding to analysis tools
- **No Popup Interruptions**: Streamlined workflow without confirmation dialogs
- **Batch Processing**: Analyze multiple requests simultaneously

## 📦 Installation

### Prerequisites
- **Burp Suite Professional/Community** (Version 2023.12+ recommended)
- **Java 17+** (For building from source)
- **Maven 3.6+** (For building from source)
- **Burp Montoya API** (Included in Burp Suite 2023.12+)

### Option 1: Pre-built JAR
1. Download the latest `JWT.jar` from the `out/artifacts/JWT_jar/` directory
2. Open Burp Suite
3. Go to **Extensions** → **Extensions** → **Add**
4. Select the JWT.jar file
5. Click **Next** → Verify "JWT Manager" appears in the loaded extensions list

### Option 2: Build from Source

#### Using Maven (Recommended)
```bash
# Clone the repository
git clone https://github.com/railroader/JWT.git
cd JWT

# Build with Maven
mvn clean package

# The JAR will be created at: target/jwt-burp-extension-1.0.0.jar
```

#### Using IntelliJ IDEA
1. Open the project in IntelliJ IDEA
2. Build → Build Artifacts → JWT:jar → Build
3. JAR will be in `out/artifacts/JWT_jar/`

## 🧪 Testing with DummyAPI

A companion testing server is available for safely testing the extension's features:

### DummyAPI Server
- **Repository**: https://github.com/railroader/DummyAPI
- **Purpose**: Provides an intentionally vulnerable JWT implementation for testing
- **Features**: 
  - 10 HTTP endpoints (8 GET, 2 POST)
  - JWT authentication with extensive PII in tokens
  - 2-minute token expiration
  - Weak JWT secret: `123456789` (HS256)
  - Test credentials:
    - `alice`/`password123` (admin role)
    - `bob`/`secret456` (user role)

### Quick Setup
```bash
# Clone and start the DummyAPI server
git clone https://github.com/railroader/DummyAPI.git
cd DummyAPI
npm install
npm start

# Server runs on http://localhost:3000
```

### Testing Workflow
1. Start DummyAPI server on `http://localhost:3000`
2. Configure JWT Manager's Session Management:
   - Auth URL: `http://localhost:3000/auth`
   - Method: `POST`
   - Username: `alice`
   - Password: `password123`
   - Token Property: `token`
3. Test authentication with "Test Login" button
4. Access protected endpoints like `/users` or `/devices`
5. Use Attack Tools to test vulnerabilities:
   - Brute force the weak secret `123456789`
   - Test none algorithm attack
   - Analyze PII exposure in tokens

## 🎮 Usage Guide

### Quick Start
1. **Install the extension** following the installation steps above
2. **Navigate to the JWT Manager tab** in Burp Suite
3. **Right-click any request** in Proxy/Repeater and select **"Send to JWT Tools"**
4. **Analyze JWT tokens** automatically detected in the request
5. **Perform security tests** using the Attack Tools and Brute Force tabs

### Session Management Setup

1. **Configure Authentication**:
   - Set auth URL endpoint
   - Choose HTTP method (GET/POST)
   - Configure username/password
   - Set token property name (e.g., "token", "access_token")
   - Preview the request before testing

2. **Enable Session Management**:
   - Click "Extension Enabled" checkbox
   - Configure JWT header name (default: "Authorization")
   - Set token prefix (default: "Bearer ")
   - Add target scope in Burp's Target → Scope

3. **Monitor API Calls**:
   - View real-time JWT usage in API Calls Monitor
   - Track HTTP response codes
   - See JWT injection and refresh events
   - Filter by token type and status

### JWT Security Analysis

#### Automatic Vulnerability Detection
The extension automatically scans for:

- **Algorithm Vulnerabilities**: None algorithm, weak HMAC secrets, non-standard algorithms
- **Data Exposure**: PII leakage (SSN, credit cards, emails, phone numbers)
- **Injection Vulnerabilities**: XSS, SQL injection, command injection patterns
- **Time-based Attacks**: Token expiration and timing analysis
- **Signature Bypass**: Various signature manipulation techniques
- **CVE Detection**: Known JWT vulnerabilities and exploits

#### Security Analysis Report Example
```
Security Analysis Summary:
├── 🔴 Critical: 2 findings
├── 🟠 High: 5 findings  
├── 🟡 Medium: 3 findings
├── 🔵 Low: 1 finding
└── ℹ️ Info: 4 findings

Critical Findings:
• Algorithm: 'none' - Token accepts no signature verification
• CVE-2022-21449: ECDSA signature bypass vulnerability detected

Recommendations:
• Enforce strong signature algorithms (RS256, PS256)
• Implement proper signature verification
• Remove sensitive data from JWT payload
• Use short expiration times (≤1 hour)
```

### Attack Tools Usage

**None Algorithm Attack**:
1. Send request to Attack Tools tab
2. Click "Test 'none' Algorithm"
3. Review results:
   - ✅ 200 OK: VULNERABLE (accepts unsigned tokens)
   - ❌ 401/403: SECURE (rejects unsigned tokens)

**Algorithm Confusion Attack**:
1. Click "Algorithm Confusion" button
2. Tests multiple algorithm variants automatically
3. Results show which algorithms are accepted

**Brute Force Attack**:
1. Navigate to Brute Force tab
2. Select wordlist file or use default weak secrets
3. Click "Start Brute Force"
4. Monitor progress and found keys

## 🏗️ Architecture

### Core Components

#### JWT Tools (`JWTTools.java`)
- Complete JWT analysis and decoding interface
- Multi-tab display: Header, Payload, Signature, Security Analysis
- Interactive token editing with real-time validation

#### Attack Tools (`AttackTools.java`)
- Automated JWT security testing suite
- Implements common JWT attack vectors
- Detailed vulnerability reporting

#### Brute Force (`BruteForce.java`)
- High-performance JWT secret discovery
- Multi-threaded wordlist processing
- Support for custom wordlists

#### Session Management (`SessionManagement.java`)
- Reactive JWT vault system
- Automatic token injection for in-scope requests
- 401-triggered re-authentication
- API call monitoring and analysis

### Session Management Workflow

```
1. Request Detection
   ↓
2. Check Scope (Burp Target Scope)
   ↓
3. If JWT in Vault → Inject into Request
   ↓
4. Send Request
   ↓
5. If 401 Response → Trigger Re-authentication
   ↓
6. Update Vault with New JWT
   ↓
7. Next Request Uses New JWT
```

## 🔒 Security Features

### Vulnerability Detection Matrix

| Attack Type | Description | Severity | Detection Method |
|-------------|-------------|----------|------------------|
| None Algorithm | Tests unsigned token acceptance | 🔴 Critical | Signature removal |
| Algorithm Confusion | RSA→HMAC confusion attacks | 🔴 Critical | Algorithm substitution |
| Weak HMAC Secrets | Common password brute force | 🟠 High | Dictionary attack |
| CVE-2022-21449 | Psychic signatures in ECDSA | 🔴 Critical | Signature analysis |
| Data Exposure | PII leakage detection | 🟡 Medium | Pattern matching |
| Injection Attacks | XSS/SQLi in claims | 🟠 High | Payload analysis |

### Best Practices Enforcement
- Warns about weak algorithms (HS256 with weak secrets)
- Detects sensitive data in tokens
- Identifies missing security claims
- Suggests secure configuration

## 🔧 Configuration

### Extension Settings
- **Extension Enabled**: Master on/off switch for session management
- **API Configuration**: Authentication endpoint settings
- **Preview Request**: View exact HTTP request before testing
- **Clear JWT Vault**: Remove stored JWT tokens

### Session Management Configuration
The extension uses a reactive JWT vault approach:
1. Stores valid JWT tokens in memory ("vault")
2. Automatically injects vault JWT into outgoing requests
3. On 401 responses, re-authenticates and updates vault
4. Only processes requests within Burp's configured scope

### Brute Force Settings
- Custom wordlist file selection
- Thread count configuration (be mindful of target server)
- Algorithm selection (HS256, HS384, HS512)

## 🐛 Troubleshooting

### Common Issues

**JWT not detected**:
- Verify JWT format (header.payload.signature)
- Check token location (Authorization header, cookies, body)
- Ensure proper Base64URL encoding

**Session management not working**:
1. Verify extension is enabled
2. Check Burp Target Scope configuration
3. Test authentication manually first
4. Review auth endpoint configuration
5. Check API Calls Monitor for details

**401 responses despite valid JWT**:
- Token may be expired (check payload exp claim)
- Server may require additional headers
- Scope configuration may be incorrect

**Brute force taking too long**:
- Use smaller, targeted wordlists
- Common weak secrets: `secret`, `123456`, `password123`
- Consider the algorithm's computational cost

### Debug Information
- Check Burp Suite → Extensions → Output/Errors tabs
- API Calls Monitor shows all JWT-related traffic
- Preview Request button helps verify auth configuration

## 🤝 Contributing

We welcome contributions! Areas for improvement:
- Additional attack vectors
- Enhanced UI components
- Performance optimizations
- Documentation improvements

### Development Guidelines
- Java 17 compatible code only
- No external dependencies (Burp API only)
- Each class in separate file
- Avoid blocking Burp UI thread
- Add comprehensive error handling

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## 🙏 Acknowledgments

- **Burp Suite Team** for the excellent Montoya API
- **JWT Security Community** for vulnerability research
- **Contributors** who helped improve this extension

---

**Happy JWT Hunting!** 🎯

*Made with ❤️ by the security community*