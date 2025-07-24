import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;

/**
 * Advanced JWT parser with enhanced validation, security checks and immutability
 * Implements best practices from professional JWT analyzers with CVE detection
 */
public final class AdvancedJWTParser {
    private static final JWTExtensionLogger logger = JWTExtensionLogger.getLogger(AdvancedJWTParser.class);
    private static final JWTResourceTracker resourceTracker = new JWTResourceTracker();
    
    // Enhanced JWT validation patterns
    private static final Pattern JWT_STRUCTURE_PATTERN = Pattern.compile(
        "^([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]*)$"
    );
    
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+$");
    
    // Algorithm validation sets
    private static final Set<String> HMAC_ALGORITHMS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("HS256", "HS384", "HS512"))
    );
    
    private static final Set<String> RSA_ALGORITHMS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"))
    );
    
    private static final Set<String> ECDSA_ALGORITHMS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("ES256", "ES384", "ES512"))
    );
    
    private static final Set<String> VULNERABLE_ALGORITHMS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("none", "None", "NONE", "NoNe", "nOnE"))
    );
    
    // Security vulnerability patterns
    private static final Pattern CVE_2022_21449_PATTERN = Pattern.compile("ES\\d{3}");
    private static final Pattern JWK_INJECTION_PATTERN = Pattern.compile("\"jwk\"\\s*:");
    private static final Pattern JKU_INJECTION_PATTERN = Pattern.compile("\"jku\"\\s*:");
    private static final Pattern X5U_INJECTION_PATTERN = Pattern.compile("\"x5u\"\\s*:");
    private static final Pattern KID_TRAVERSAL_PATTERN = Pattern.compile("\"kid\"\\s*:\\s*\"[./\\\\]+");
    
    // Cache for parsed results (thread-safe with size limit)
    private static final Map<String, ParsedJWTResult> PARSER_CACHE = new ConcurrentHashMap<>();
    private static final int MAX_CACHE_SIZE = 2000;
    
    /**
     * Immutable result class containing parsed JWT data and security findings
     */
    public static final class ParsedJWTResult {
        private final String originalToken;
        private final JWTComponents components;
        private final Map<String, Object> header;
        private final Map<String, Object> payload;
        private final List<SecurityFinding> securityFindings;
        private final ValidationResult validation;
        private final String parseId;
        private final long parseTimestamp;
        
        private ParsedJWTResult(Builder builder) {
            this.originalToken = builder.originalToken;
            this.components = builder.components;
            this.header = Collections.unmodifiableMap(new LinkedHashMap<>(builder.header));
            this.payload = Collections.unmodifiableMap(new LinkedHashMap<>(builder.payload));
            this.securityFindings = Collections.unmodifiableList(new ArrayList<>(builder.securityFindings));
            this.validation = builder.validation;
            this.parseId = UUID.randomUUID().toString();
            this.parseTimestamp = System.currentTimeMillis();
        }
        
        // Immutable getters
        public String getOriginalToken() { return originalToken; }
        public JWTComponents getComponents() { return components; }
        public Map<String, Object> getHeader() { return header; }
        public Map<String, Object> getPayload() { return payload; }
        public List<SecurityFinding> getSecurityFindings() { return securityFindings; }
        public ValidationResult getValidation() { return validation; }
        public String getParseId() { return parseId; }
        public long getParseTimestamp() { return parseTimestamp; }
        
        public String getAlgorithm() {
            return (String) header.get("alg");
        }
        
        public Long getExpirationTime() {
            Object exp = payload.get("exp");
            return exp instanceof Number ? ((Number) exp).longValue() : null;
        }
        
        public boolean isExpired() {
            Long exp = getExpirationTime();
            return exp != null && exp < (System.currentTimeMillis() / 1000);
        }
        
        public boolean hasSecurityIssues() {
            return !securityFindings.isEmpty();
        }
        
        public boolean isCriticalVulnerable() {
            return securityFindings.stream()
                .anyMatch(finding -> "critical".equals(finding.getSeverity()));
        }
        
        static class Builder {
            String originalToken;
            JWTComponents components;
            Map<String, Object> header = new LinkedHashMap<>();
            Map<String, Object> payload = new LinkedHashMap<>();
            List<SecurityFinding> securityFindings = new ArrayList<>();
            ValidationResult validation;
            
            Builder setOriginalToken(String token) { this.originalToken = token; return this; }
            Builder setComponents(JWTComponents comp) { this.components = comp; return this; }
            Builder setHeader(Map<String, Object> header) { this.header = header; return this; }
            Builder setPayload(Map<String, Object> payload) { this.payload = payload; return this; }
            Builder addSecurityFinding(SecurityFinding finding) { this.securityFindings.add(finding); return this; }
            Builder setValidation(ValidationResult validation) { this.validation = validation; return this; }
            
            ParsedJWTResult build() { return new ParsedJWTResult(this); }
        }
    }
    
    /**
     * Immutable JWT components class
     */
    public static final class JWTComponents {
        private final String encodedHeader;
        private final String encodedPayload;
        private final String encodedSignature;
        private final String headerJson;
        private final String payloadJson;
        private final byte[] signature;
        
        public JWTComponents(String encodedHeader, String encodedPayload, String encodedSignature,
                           String headerJson, String payloadJson, byte[] signature) {
            this.encodedHeader = encodedHeader;
            this.encodedPayload = encodedPayload;
            this.encodedSignature = encodedSignature;
            this.headerJson = headerJson;
            this.payloadJson = payloadJson;
            this.signature = signature != null ? signature.clone() : null;
        }
        
        public String getEncodedHeader() { return encodedHeader; }
        public String getEncodedPayload() { return encodedPayload; }
        public String getEncodedSignature() { return encodedSignature; }
        public String getHeaderJson() { return headerJson; }
        public String getPayloadJson() { return payloadJson; }
        public byte[] getSignature() { return signature != null ? signature.clone() : null; }
        
        public String reconstructToken() {
            return encodedHeader + "." + encodedPayload + "." + encodedSignature;
        }
        
        public String getUnsignedToken() {
            return encodedHeader + "." + encodedPayload + ".";
        }
    }
    
    /**
     * Validation result with detailed error information
     */
    public static final class ValidationResult {
        private final boolean isValid;
        private final List<String> errors;
        private final List<String> warnings;
        private final Map<String, Object> metadata;
        
        public ValidationResult(boolean isValid, List<String> errors, List<String> warnings, Map<String, Object> metadata) {
            this.isValid = isValid;
            this.errors = Collections.unmodifiableList(new ArrayList<>(errors));
            this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
            this.metadata = Collections.unmodifiableMap(new LinkedHashMap<>(metadata));
        }
        
        public boolean isValid() { return isValid; }
        public List<String> getErrors() { return errors; }
        public List<String> getWarnings() { return warnings; }
        public Map<String, Object> getMetadata() { return metadata; }
    }
    
    /**
     * Parse JWT with comprehensive validation and security analysis
     */
    public static ParsedJWTResult parseWithSecurityAnalysis(String token) throws JWTExtensionException {
        if (token == null || token.trim().isEmpty()) {
            throw new JWTTokenParseException("Token cannot be null or empty", token);
        }
        
        String cleanToken = cleanToken(token);
        String resourceId = "AdvancedJWTParser-" + cleanToken.hashCode();
        
        try {
            resourceTracker.trackResource(resourceId);
            
            // Check cache first
            ParsedJWTResult cached = PARSER_CACHE.get(cleanToken);
            if (cached != null) {
                logger.trace("Retrieved parsed JWT from cache");
                return cached;
            }
            
            // Manage cache size
            if (PARSER_CACHE.size() >= MAX_CACHE_SIZE) {
                PARSER_CACHE.clear();
                logger.debug("Cleared JWT parser cache due to size limit");
            }
            
            ParsedJWTResult.Builder resultBuilder = new ParsedJWTResult.Builder()
                .setOriginalToken(cleanToken);
            
            // Phase 1: Structure validation
            JWTComponents components = parseStructure(cleanToken, resultBuilder);
            resultBuilder.setComponents(components);
            
            // Phase 2: Parse header and payload
            Map<String, Object> header = parseJsonComponent(components.getHeaderJson(), "header");
            Map<String, Object> payload = parseJsonComponent(components.getPayloadJson(), "payload");
            resultBuilder.setHeader(header).setPayload(payload);
            
            // Phase 3: Comprehensive validation
            ValidationResult validation = performComprehensiveValidation(components, header, payload);
            resultBuilder.setValidation(validation);
            
            // Phase 4: Security analysis
            performSecurityAnalysis(header, payload, components, resultBuilder);
            
            ParsedJWTResult result = resultBuilder.build();
            
            // Cache the result
            PARSER_CACHE.put(cleanToken, result);
            
            logger.debug("Successfully parsed JWT with %d security findings", result.getSecurityFindings().size());
            
            return result;
            
        } catch (Exception e) {
            logger.error("Failed to parse JWT: %s", e.getMessage());
            throw new JWTTokenParseException("JWT parsing failed: " + e.getMessage(), token, e);
        } finally {
            resourceTracker.releaseResource(resourceId);
        }
    }
    
    /**
     * Parse JWT structure into components
     */
    private static JWTComponents parseStructure(String token, ParsedJWTResult.Builder resultBuilder) 
            throws JWTExtensionException {
        
        Matcher matcher = JWT_STRUCTURE_PATTERN.matcher(token);
        if (!matcher.matches()) {
            throw new JWTTokenParseException("Invalid JWT structure - must have 3 parts separated by dots", token);
        }
        
        String encodedHeader = matcher.group(1);
        String encodedPayload = matcher.group(2);
        String encodedSignature = matcher.group(3);
        
        // Validate Base64URL encoding
        if (!isValidBase64URL(encodedHeader)) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Structure", "high", 
                "Invalid Base64URL encoding in header"));
        }
        
        if (!isValidBase64URL(encodedPayload)) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Structure", "high", 
                "Invalid Base64URL encoding in payload"));
        }
        
        if (!encodedSignature.isEmpty() && !isValidBase64URL(encodedSignature)) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Structure", "medium", 
                "Invalid Base64URL encoding in signature"));
        }
        
        // Decode components
        String headerJson = decodeBase64URL(encodedHeader);
        String payloadJson = decodeBase64URL(encodedPayload);
        byte[] signature = encodedSignature.isEmpty() ? new byte[0] : 
            decodeBase64URLBytes(encodedSignature);
        
        return new JWTComponents(encodedHeader, encodedPayload, encodedSignature,
                               headerJson, payloadJson, signature);
    }
    
    /**
     * Parse JSON component with validation
     */
    private static Map<String, Object> parseJsonComponent(String json, String componentName) 
            throws JWTExtensionException {
        
        if (json == null || json.trim().isEmpty()) {
            throw new JWTTokenParseException("Empty " + componentName + " component", json);
        }
        
        try {
            return parseJson(json);
        } catch (Exception e) {
            throw new JWTTokenParseException("Invalid JSON in " + componentName + ": " + e.getMessage(), json, e);
        }
    }
    
    /**
     * Comprehensive validation including algorithm and claim validation
     */
    private static ValidationResult performComprehensiveValidation(JWTComponents components, 
            Map<String, Object> header, Map<String, Object> payload) {
        
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Map<String, Object> metadata = new LinkedHashMap<>();
        
        // Algorithm validation
        Object algObj = header.get("alg");
        if (algObj == null) {
            errors.add("Missing 'alg' claim in header");
        } else {
            String algorithm = algObj.toString();
            metadata.put("algorithm", algorithm);
            
            if (VULNERABLE_ALGORITHMS.contains(algorithm)) {
                errors.add("Vulnerable algorithm detected: " + algorithm);
            }
            
            if (!HMAC_ALGORITHMS.contains(algorithm) && 
                !RSA_ALGORITHMS.contains(algorithm) && 
                !ECDSA_ALGORITHMS.contains(algorithm) && 
                !"none".equals(algorithm)) {
                warnings.add("Unknown or non-standard algorithm: " + algorithm);
            }
        }
        
        // Time claims validation
        validateTimeClaims(payload, warnings, metadata);
        
        // Critical claims validation
        validateCriticalClaims(header, payload, errors, warnings);
        
        boolean isValid = errors.isEmpty();
        return new ValidationResult(isValid, errors, warnings, metadata);
    }
    
    /**
     * Validate time-based claims
     */
    private static void validateTimeClaims(Map<String, Object> payload, List<String> warnings, 
            Map<String, Object> metadata) {
        
        long currentTime = System.currentTimeMillis() / 1000;
        
        // Expiration time
        Object expObj = payload.get("exp");
        if (expObj instanceof Number) {
            long exp = ((Number) expObj).longValue();
            metadata.put("expirationTime", exp);
            if (exp < currentTime) {
                warnings.add("Token has expired");
            }
        }
        
        // Not before time
        Object nbfObj = payload.get("nbf");
        if (nbfObj instanceof Number) {
            long nbf = ((Number) nbfObj).longValue();
            metadata.put("notBefore", nbf);
            if (nbf > currentTime) {
                warnings.add("Token is not yet valid (nbf claim)");
            }
        }
        
        // Issued at time
        Object iatObj = payload.get("iat");
        if (iatObj instanceof Number) {
            long iat = ((Number) iatObj).longValue();
            metadata.put("issuedAt", iat);
            if (iat > currentTime + 300) { // 5 minute clock skew tolerance
                warnings.add("Token issued in the future");
            }
        }
    }
    
    /**
     * Validate critical claims and required fields
     */
    private static void validateCriticalClaims(Map<String, Object> header, Map<String, Object> payload,
            List<String> errors, List<String> warnings) {
        
        // Check for critical header parameter
        Object crit = header.get("crit");
        if (crit instanceof List) {
            List<?> critList = (List<?>) crit;
            for (Object critClaim : critList) {
                if (critClaim instanceof String) {
                    String claimName = (String) critClaim;
                    if (!header.containsKey(claimName)) {
                        errors.add("Critical claim '" + claimName + "' is missing from header");
                    }
                }
            }
        }
        
        // Common security-relevant claims
        if (!payload.containsKey("iss")) {
            warnings.add("Missing 'iss' (issuer) claim - reduces token traceability");
        }
        
        if (!payload.containsKey("aud")) {
            warnings.add("Missing 'aud' (audience) claim - increases replay attack risk");
        }
        
        if (!payload.containsKey("exp")) {
            warnings.add("Missing 'exp' (expiration) claim - token never expires");
        }
    }
    
    /**
     * Comprehensive security analysis inspired by professional JWT tools
     */
    private static void performSecurityAnalysis(Map<String, Object> header, Map<String, Object> payload,
            JWTComponents components, ParsedJWTResult.Builder resultBuilder) {
        
        // CVE-2022-21449 detection (Psychic Signatures)
        detectCVE202221449(header, resultBuilder);
        
        // Algorithm confusion attacks
        detectAlgorithmConfusion(header, resultBuilder);
        
        // Header injection attacks
        detectHeaderInjections(header, resultBuilder);
        
        // Key confusion attacks
        detectKeyConfusion(header, resultBuilder);
        
        // Signature bypass attempts
        detectSignatureBypass(components, resultBuilder);
        
        // Timing attack vulnerabilities
        detectTimingVulnerabilities(payload, resultBuilder);
        
        // Privilege escalation risks
        detectPrivilegeEscalation(payload, resultBuilder);
        
        // Information disclosure
        detectInformationDisclosure(payload, resultBuilder);
        
        // Replay attack vulnerabilities
        detectReplayVulnerabilities(payload, resultBuilder);
    }
    
    /**
     * Detect CVE-2022-21449 vulnerability (Psychic Signatures)
     */
    private static void detectCVE202221449(Map<String, Object> header, ParsedJWTResult.Builder resultBuilder) {
        Object algObj = header.get("alg");
        if (algObj instanceof String) {
            String algorithm = (String) algObj;
            if (CVE_2022_21449_PATTERN.matcher(algorithm).matches()) {
                resultBuilder.addSecurityFinding(new SecurityFinding("CVE-2022-21449", "critical",
                    "ECDSA algorithm detected - Vulnerable to CVE-2022-21449 (Psychic Signatures) in Java 15-18. " +
                    "Attackers can bypass signature verification with invalid signatures.",
                    "Algorithm: " + algorithm));
            }
        }
    }
    
    /**
     * Detect algorithm confusion attacks
     */
    private static void detectAlgorithmConfusion(Map<String, Object> header, ParsedJWTResult.Builder resultBuilder) {
        Object algObj = header.get("alg");
        if (algObj instanceof String) {
            String algorithm = (String) algObj;
            
            // None algorithm detection
            if (VULNERABLE_ALGORITHMS.contains(algorithm)) {
                resultBuilder.addSecurityFinding(new SecurityFinding("Algorithm Confusion", "critical",
                    "Vulnerable 'none' algorithm variant detected. Token can be accepted without signature verification.",
                    "Algorithm: " + algorithm));
            }
            
            // HMAC on RSA confusion
            if (HMAC_ALGORITHMS.contains(algorithm)) {
                resultBuilder.addSecurityFinding(new SecurityFinding("Algorithm Confusion", "high",
                    "HMAC algorithm detected - Vulnerable to RSA-to-HMAC confusion if server expects RSA. " +
                    "Attacker can use public key as HMAC secret.",
                    "Algorithm: " + algorithm));
            }
            
            // Case variation detection
            String lowerAlg = algorithm.toLowerCase();
            if (!algorithm.equals(lowerAlg) || !algorithm.equals(algorithm.toUpperCase())) {
                resultBuilder.addSecurityFinding(new SecurityFinding("Algorithm Confusion", "medium",
                    "Non-standard algorithm casing detected - May bypass strict algorithm validation.",
                    "Algorithm: " + algorithm));
            }
        }
    }
    
    /**
     * Detect header injection attacks
     */
    private static void detectHeaderInjections(Map<String, Object> header, ParsedJWTResult.Builder resultBuilder) {
        // JWK injection
        if (header.containsKey("jwk")) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Header Injection", "critical",
                "JWK header injection detected - Attacker can embed their own public key for signature verification.",
                "JWK: " + header.get("jwk").toString().substring(0, Math.min(100, header.get("jwk").toString().length()))));
        }
        
        // JKU injection
        if (header.containsKey("jku")) {
            String jku = header.get("jku").toString();
            resultBuilder.addSecurityFinding(new SecurityFinding("Header Injection", "high",
                "JKU header detected - Server may fetch keys from attacker-controlled URL.",
                "JKU: " + jku));
        }
        
        // X5U injection
        if (header.containsKey("x5u")) {
            String x5u = header.get("x5u").toString();
            resultBuilder.addSecurityFinding(new SecurityFinding("Header Injection", "high",
                "X5U header detected - Server may fetch certificate from attacker-controlled URL.",
                "X5U: " + x5u));
        }
        
        // KID path traversal
        if (header.containsKey("kid")) {
            String kid = header.get("kid").toString();
            if (kid.contains("../") || kid.contains("..\\") || kid.contains("/dev/null")) {
                resultBuilder.addSecurityFinding(new SecurityFinding("Path Traversal", "high",
                    "KID path traversal detected - May allow reading arbitrary files or using null keys.",
                    "KID: " + kid));
            }
        }
    }
    
    /**
     * Detect key confusion attacks
     */
    private static void detectKeyConfusion(Map<String, Object> header, ParsedJWTResult.Builder resultBuilder) {
        Object algObj = header.get("alg");
        Object kidObj = header.get("kid");
        
        if (algObj instanceof String && kidObj instanceof String) {
            String algorithm = (String) algObj;
            String kid = (String) kidObj;
            
            // Weak KID values
            if (kid.isEmpty() || "null".equals(kid) || "0".equals(kid)) {
                resultBuilder.addSecurityFinding(new SecurityFinding("Key Confusion", "medium",
                    "Weak KID value detected - May default to weak or predictable keys.",
                    "KID: " + kid));
            }
            
            // SQL injection in KID
            if (kid.contains("'") || kid.contains("\"") || kid.contains(";")) {
                resultBuilder.addSecurityFinding(new SecurityFinding("SQL Injection", "high",
                    "Potential SQL injection in KID parameter.",
                    "KID: " + kid));
            }
        }
    }
    
    /**
     * Detect signature bypass attempts
     */
    private static void detectSignatureBypass(JWTComponents components, ParsedJWTResult.Builder resultBuilder) {
        String signature = components.getEncodedSignature();
        
        // Empty signature
        if (signature.isEmpty()) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Signature Bypass", "critical",
                "Empty signature detected - Token may be accepted without verification."));
        }
        
        // Signature length analysis
        if (signature.length() < 10) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Signature Bypass", "high",
                "Unusually short signature detected - May indicate tampering or weak signature.",
                "Signature length: " + signature.length()));
        }
    }
    
    /**
     * Detect timing attack vulnerabilities
     */
    private static void detectTimingVulnerabilities(Map<String, Object> payload, ParsedJWTResult.Builder resultBuilder) {
        // Check for timing-sensitive claims
        if (!payload.containsKey("iat")) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Timing Attack", "medium",
                "Missing 'iat' claim - Difficult to detect replay attacks and timing anomalies."));
        }
        
        if (!payload.containsKey("jti")) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Replay Attack", "medium",
                "Missing 'jti' (JWT ID) claim - Token replay attacks cannot be prevented."));
        }
    }
    
    /**
     * Detect privilege escalation risks
     */
    private static void detectPrivilegeEscalation(Map<String, Object> payload, ParsedJWTResult.Builder resultBuilder) {
        // Check for privilege-related claims
        Object rolesObj = payload.get("roles");
        Object scopeObj = payload.get("scope");
        Object permissionsObj = payload.get("permissions");
        
        if (rolesObj != null || scopeObj != null || permissionsObj != null) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Privilege Escalation", "info",
                "Authorization claims detected - Verify server validates these claims properly.",
                "Claims: roles=" + (rolesObj != null) + ", scope=" + (scopeObj != null) + 
                ", permissions=" + (permissionsObj != null)));
        }
        
        // Admin role detection
        if (rolesObj != null && rolesObj.toString().toLowerCase().contains("admin")) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Privilege Escalation", "medium",
                "Admin role detected in token - High-value target for privilege escalation.",
                "Roles: " + rolesObj.toString()));
        }
    }
    
    /**
     * Detect information disclosure vulnerabilities
     */
    private static void detectInformationDisclosure(Map<String, Object> payload, ParsedJWTResult.Builder resultBuilder) {
        // Check for sensitive data patterns
        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            String key = entry.getKey().toLowerCase();
            String value = entry.getValue().toString();
            
            // Email detection
            if (key.contains("email") && value.contains("@")) {
                resultBuilder.addSecurityFinding(new SecurityFinding("Information Disclosure", "low",
                    "Email address exposed in token payload.",
                    "Field: " + entry.getKey() + " = " + value));
            }
            
            // Phone number detection
            if (key.contains("phone") && value.matches(".*\\d{3}.*\\d{3}.*\\d{4}.*")) {
                resultBuilder.addSecurityFinding(new SecurityFinding("Information Disclosure", "low",
                    "Phone number pattern detected in token payload.",
                    "Field: " + entry.getKey() + " = " + value));
            }
            
            // SSN detection
            if (value.matches(".*\\d{3}-\\d{2}-\\d{4}.*")) {
                resultBuilder.addSecurityFinding(new SecurityFinding("Information Disclosure", "high",
                    "Social Security Number pattern detected in token payload.",
                    "Field: " + entry.getKey()));
            }
        }
    }
    
    /**
     * Detect replay attack vulnerabilities
     */
    private static void detectReplayVulnerabilities(Map<String, Object> payload, ParsedJWTResult.Builder resultBuilder) {
        boolean hasNonce = payload.containsKey("nonce");
        boolean hasJti = payload.containsKey("jti");
        boolean hasExp = payload.containsKey("exp");
        
        if (!hasNonce && !hasJti) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Replay Attack", "medium",
                "No replay protection detected - Missing both 'nonce' and 'jti' claims."));
        }
        
        if (!hasExp) {
            resultBuilder.addSecurityFinding(new SecurityFinding("Replay Attack", "high",
                "Token never expires - Indefinite replay attack window."));
        }
    }
    
    // Utility methods
    private static String cleanToken(String token) {
        return token.trim().replaceAll("^Bearer\\s+", "");
    }
    
    private static boolean isValidBase64URL(String str) {
        return BASE64_PATTERN.matcher(str).matches();
    }
    
    private static String decodeBase64URL(String encoded) throws JWTExtensionException {
        try {
            return new String(decodeBase64URLBytes(encoded), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new JWTTokenParseException("Failed to decode Base64URL: " + e.getMessage(), encoded, e);
        }
    }
    
    private static byte[] decodeBase64URLBytes(String encoded) throws JWTExtensionException {
        try {
            String padded = encoded;
            int padding = (4 - encoded.length() % 4) % 4;
            for (int i = 0; i < padding; i++) {
                padded += "=";
            }
            return Base64.getUrlDecoder().decode(padded);
        } catch (Exception e) {
            throw new JWTTokenParseException("Failed to decode Base64URL bytes: " + e.getMessage(), encoded, e);
        }
    }
    
    private static Map<String, Object> parseJson(String json) throws JWTExtensionException {
        // Simple JSON parser implementation for basic JWT claims
        Map<String, Object> result = new LinkedHashMap<>();
        
        if (json == null || json.trim().isEmpty()) {
            return result;
        }
        
        json = json.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) {
            throw new JWTTokenParseException("Invalid JSON format", json);
        }
        
        // Remove outer braces
        json = json.substring(1, json.length() - 1).trim();
        
        if (json.isEmpty()) {
            return result;
        }
        
        // Simple key-value parser
        String[] pairs = json.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
        
        for (String pair : pairs) {
            pair = pair.trim();
            int colonIndex = pair.indexOf(":");
            if (colonIndex > 0) {
                String key = pair.substring(0, colonIndex).trim();
                String value = pair.substring(colonIndex + 1).trim();
                
                // Remove quotes from key
                if (key.startsWith("\"") && key.endsWith("\"")) {
                    key = key.substring(1, key.length() - 1);
                }
                
                // Parse value
                Object parsedValue = parseJsonValue(value);
                result.put(key, parsedValue);
            }
        }
        
        return result;
    }
    
    private static Object parseJsonValue(String value) {
        value = value.trim();
        
        if (value.equals("null")) {
            return null;
        } else if (value.equals("true")) {
            return true;
        } else if (value.equals("false")) {
            return false;
        } else if (value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        } else if (value.startsWith("[") && value.endsWith("]")) {
            // Simple array parsing
            List<Object> list = new ArrayList<>();
            String arrayContent = value.substring(1, value.length() - 1).trim();
            if (!arrayContent.isEmpty()) {
                String[] elements = arrayContent.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                for (String element : elements) {
                    list.add(parseJsonValue(element.trim()));
                }
            }
            return list;
        } else {
            // Try to parse as number
            try {
                if (value.contains(".")) {
                    return Double.parseDouble(value);
                } else {
                    return Long.parseLong(value);
                }
            } catch (NumberFormatException e) {
                return value; // Return as string if not a number
            }
        }
    }
    
    // Prevent instantiation
    private AdvancedJWTParser() {}
}
