import burp.api.montoya.MontoyaApi;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

/**
 * Performs comprehensive security analysis of JWT tokens
 * Enhanced with intelligent analysis techniques
 */
public class JWTSecurityAnalyzer {
    private MontoyaApi api;
    
    // Security patterns for detection
    private static final Pattern EMAIL_PATTERN = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");
    private static final Pattern PHONE_PATTERN = Pattern.compile("\\b(?:\\+?1[-\\.\\s]?)?\\(?([0-9]{3})\\)?[-\\.\\s]?([0-9]{3})[-\\.\\s]?([0-9]{4})\\b");
    private static final Pattern SSN_PATTERN = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b");
    
    // XSS patterns
    private static final Pattern[] XSS_PATTERNS = {
        Pattern.compile("<script", Pattern.CASE_INSENSITIVE),
        Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<iframe", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<object", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<embed", Pattern.CASE_INSENSITIVE),
        Pattern.compile("document\\."),
        Pattern.compile("window\\."),
        Pattern.compile("eval\\(")
    };
    
    // SQL Injection patterns
    private static final Pattern[] SQL_PATTERNS = {
        Pattern.compile("(\\b(union|select|insert|update|delete|drop|create)\\b.*\\b(from|into|where|table)\\b)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("('|\")\\s*(or|and)\\s*('|\")?((\\d|[a-z]))", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b(exec|execute)\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile(";\\s*(drop|delete|insert|update)", Pattern.CASE_INSENSITIVE)
    };
    
    public JWTSecurityAnalyzer(MontoyaApi api) {
        this.api = api;
    }
    
    /**
     * Perform comprehensive security analysis of JWT token
     * Enhanced with intelligent detection techniques
     */
    public SecurityAnalysisResult analyzeToken(String headerJson, String payloadJson) {
        SecurityAnalysisResult result = new SecurityAnalysisResult();
        
        try {
            // Enhanced analysis pipeline
            analyzeTokenStructure(headerJson, payloadJson, result);
            analyzeAlgorithmVulnerabilities(headerJson, result);
            analyzeSignatureIssues(headerJson, result);
            analyzePayloadSecurity(payloadJson, result);
            analyzeTimeBasedAttacks(payloadJson, result);
            analyzeClaimValidation(payloadJson, result);
            analyzeSensitiveDataExposure(payloadJson, result);
            analyzeInjectionVulnerabilities(payloadJson, result);
            analyzePrivilegeEscalation(payloadJson, result);
            addGeneralRecommendations(result);
            
            // Sort findings by severity
            result.sortFindingsBySeverity();
            
        } catch (Exception e) {
            api.logging().logToError("Security analysis error: " + e.getMessage());
            result.addFinding(new SecurityFinding("Analysis Error", "high", 
                "Error during security analysis: " + e.getMessage()));
        }
        
        return result;
    }
    
    private void analyzeAlgorithm(String headerJson, SecurityAnalysisResult result) {
        try {
            String alg = extractJsonValue(headerJson, "alg");
            if (alg != null) {
                alg = alg.toLowerCase();
                if (alg.startsWith("hs")) {
                    result.addFinding(new SecurityFinding("Algorithm", "high", 
                        "HMAC algorithm (" + alg.toUpperCase() + ") used - Vulnerable to key confusion attacks if expecting RSA"));
                } else if ("none".equals(alg)) {
                    result.addFinding(new SecurityFinding("Algorithm", "critical", 
                        "Algorithm 'none' detected - Token can be forged without signature verification"));
                } else if (alg.startsWith("rs") || alg.startsWith("es") || alg.startsWith("ps")) {
                    result.addFinding(new SecurityFinding("Algorithm", "info", 
                        "Asymmetric algorithm (" + alg.toUpperCase() + ") used - Good for distributed systems"));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error analyzing algorithm: " + e.getMessage());
        }
    }
    
    private void analyzeDataExposure(String payloadJson, SecurityAnalysisResult result) {
        // Check for sensitive field names and patterns
        String[] sensitiveFields = {"ssn", "social_security", "credit_card", "creditcard", "password", 
                                   "bank_account", "drivers_license", "passport", "medical_id", "tax_id"};
        
        for (String field : sensitiveFields) {
            if (containsField(payloadJson, field)) {
                String severity = "critical";
                if (field.contains("credit") || field.equals("ssn") || field.contains("bank")) {
                    severity = "critical";
                } else {
                    severity = "high";
                }
                result.addFinding(new SecurityFinding("Data Exposure", severity, 
                    "Sensitive field \"" + field + "\" found in token payload"));
            }
        }
        
        // Check for PII patterns
        if (containsEmailPattern(payloadJson)) {
            result.addFinding(new SecurityFinding("Data Exposure", "high", 
                "Potential email PII detected in token"));
        }
        
        if (containsPhonePattern(payloadJson)) {
            String phoneField = extractFieldWithPhonePattern(payloadJson);
            result.addFinding(new SecurityFinding("Data Exposure", "high", 
                "Potential phone number detected" + (phoneField != null ? " in field \"" + phoneField + "\"" : "")));
        }
        
        if (containsSSNPattern(payloadJson)) {
            result.addFinding(new SecurityFinding("Data Exposure", "high", 
                "Potential SSN PII detected in token"));
        }
        
        if (containsCreditCardPattern(payloadJson)) {
            result.addFinding(new SecurityFinding("Data Exposure", "high", 
                "Potential credit card PII detected in token"));
        }
    }
    
    private void analyzeExpiration(String payloadJson, SecurityAnalysisResult result) {
        try {
            String expStr = extractJsonValue(payloadJson, "exp");
            if (expStr != null) {
                long exp = Long.parseLong(expStr);
                long currentTime = System.currentTimeMillis() / 1000;
                
                if (exp < currentTime) {
                    long expiredMinutes = (currentTime - exp) / 60;
                    result.addFinding(new SecurityFinding("Expiration", "high", 
                        "Token is expired (expired " + expiredMinutes + " minutes ago)"));
                } else {
                    long validMinutes = (exp - currentTime) / 60;
                    if (validMinutes > 1440) { // More than 24 hours
                        result.addFinding(new SecurityFinding("Expiration", "medium", 
                            "Token has very long expiration time (" + (validMinutes / 60) + " hours)"));
                    } else {
                        result.addFinding(new SecurityFinding("Expiration", "info", 
                            "Token expires in " + validMinutes + " minutes"));
                    }
                }
            } else {
                result.addFinding(new SecurityFinding("Expiration", "high", 
                    "Missing expiration (exp) claim - Token never expires"));
            }
        } catch (Exception e) {
            api.logging().logToError("Error analyzing expiration: " + e.getMessage());
        }
    }
    
    private void analyzeClaims(String payloadJson, SecurityAnalysisResult result) {
        // Check for standard claims
        if (extractJsonValue(payloadJson, "iss") == null) {
            result.addFinding(new SecurityFinding("Claims", "medium", 
                "Missing issuer (iss) claim - Cannot verify token source"));
        }
        
        if (extractJsonValue(payloadJson, "aud") == null) {
            result.addFinding(new SecurityFinding("Claims", "medium", 
                "Missing audience (aud) claim - Token can be used on any service"));
        }
        
        if (extractJsonValue(payloadJson, "jti") == null) {
            result.addFinding(new SecurityFinding("Claims", "low", 
                "Missing JWT ID (jti) - No replay attack protection"));
        }
        
        if (extractJsonValue(payloadJson, "nbf") == null) {
            result.addFinding(new SecurityFinding("Claims", "low", 
                "Missing not-before (nbf) claim - Token valid immediately"));
        }
    }
    
    private void analyzePrivilegeEscalation(String payloadJson, SecurityAnalysisResult result) {
        // Check for privilege-related fields
        String role = extractJsonValue(payloadJson, "role");
        String roles = extractJsonValue(payloadJson, "roles");
        String permissions = extractJsonValue(payloadJson, "permissions");
        String scope = extractJsonValue(payloadJson, "scope");
        
        boolean hasPrivilegeClaims = false;
        
        if (role != null) {
            hasPrivilegeClaims = true;
            if (role.toLowerCase().contains("admin") || role.toLowerCase().contains("super") || 
                role.toLowerCase().contains("root") || role.toLowerCase().contains("elevated")) {
                result.addFinding(new SecurityFinding("Privilege Escalation", "high", 
                    "Token contains high-privilege role claims"));
            }
        }
        
        if (roles != null && (roles.toLowerCase().contains("admin") || roles.toLowerCase().contains("super"))) {
            hasPrivilegeClaims = true;
            result.addFinding(new SecurityFinding("Privilege Escalation", "high", 
                "Token contains high-privilege role claims in roles array"));
        }
        
        if (permissions != null || scope != null) {
            hasPrivilegeClaims = true;
        }
        
        if (hasPrivilegeClaims) {
            result.addFinding(new SecurityFinding("Authorization", "info", 
                "Token contains role/permission claims - Ensure proper server-side validation"));
        }
    }
    
    private void addGeneralRecommendations(SecurityAnalysisResult result) {
        result.addFinding(new SecurityFinding("Storage", "info", 
            "Recommended: Store in httpOnly, secure cookies instead of localStorage"));
        result.addFinding(new SecurityFinding("Storage", "info", 
            "Avoid storing JWTs in localStorage (XSS vulnerable) or URL parameters (logged)"));
        result.addFinding(new SecurityFinding("Transmission", "info", 
            "Always transmit JWTs over HTTPS"));
    }
    
    // Helper methods for pattern detection and JSON parsing
    private String extractJsonValue(String json, String key) {
        try {
            String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"|\"" + key + "\"\\s*:\\s*([^,}\\s]+)";
            Pattern p = Pattern.compile(pattern);
            Matcher m = p.matcher(json);
            if (m.find()) {
                return m.group(1) != null ? m.group(1) : m.group(2);
            }
        } catch (Exception e) {
            api.logging().logToError("Error extracting JSON value for key " + key + ": " + e.getMessage());
        }
        return null;
    }
    
    private boolean containsField(String json, String fieldName) {
        return json.toLowerCase().contains("\"" + fieldName.toLowerCase() + "\"");
    }
    
    private boolean containsEmailPattern(String json) {
        Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
        return emailPattern.matcher(json).find();
    }
    
    private boolean containsPhonePattern(String json) {
        Pattern phonePattern = Pattern.compile("(\\+?1[-\\s]?)?\\(?[0-9]{3}\\)?[-\\s]?[0-9]{3}[-\\s]?[0-9]{4}|[0-9]{10,12}");
        return phonePattern.matcher(json).find();
    }
    
    private String extractFieldWithPhonePattern(String json) {
        String[] phoneFields = {"phone", "mobile", "telephone", "cell", "bank_account"};
        for (String field : phoneFields) {
            if (containsField(json, field)) {
                return field;
            }
        }
        return null;
    }
    
    private boolean containsSSNPattern(String json) {
        Pattern ssnPattern = Pattern.compile("[0-9]{3}-[0-9]{2}-[0-9]{4}|[0-9]{9}");
        return ssnPattern.matcher(json).find();
    }
    
    private boolean containsCreditCardPattern(String json) {
        Pattern ccPattern = Pattern.compile("[0-9]{4}[-\\s]?[0-9]{4}[-\\s]?[0-9]{4}[-\\s]?[0-9]{4}");
        return ccPattern.matcher(json).find();
    }
    
    // Enhanced analysis methods based on JavaScript analyzer
    
    private void analyzeTokenStructure(String headerJson, String payloadJson, SecurityAnalysisResult result) {
        try {
            // Check for valid JSON structure
            if (headerJson == null || headerJson.trim().isEmpty()) {
                result.addFinding(new SecurityFinding("Token Structure", "critical", "Missing or empty header"));
            }
            if (payloadJson == null || payloadJson.trim().isEmpty()) {
                result.addFinding(new SecurityFinding("Token Structure", "critical", "Missing or empty payload"));
            }
            
            // Check payload size
            if (payloadJson != null && payloadJson.length() > 1000) {
                result.addFinding(new SecurityFinding("Data Exposure", "medium", 
                    "Large payload size (" + payloadJson.length() + " chars) - Consider minimizing data in token"));
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error analyzing token structure: " + e.getMessage());
        }
    }
    
    private void analyzeAlgorithmVulnerabilities(String headerJson, SecurityAnalysisResult result) {
        try {
            String alg = extractJsonValue(headerJson, "alg");
            if (alg == null || alg.trim().isEmpty()) {
                result.addFinding(new SecurityFinding("Algorithm", "critical", "Missing algorithm in header", headerJson));
                return;
            }
            
            String originalAlg = alg;
            alg = alg.toLowerCase();
            String algSnippet = "\"alg\":\"" + originalAlg + "\"";
            
            // Critical vulnerabilities
            if ("none".equals(alg)) {
                result.addFinding(new SecurityFinding("Algorithm", "critical", 
                    "Algorithm 'none' detected - Token has no signature verification!", algSnippet));
            }
            
            // HMAC confusion attacks
            if (alg.startsWith("hs")) {
                result.addFinding(new SecurityFinding("Algorithm", "high", 
                    "HMAC algorithm (" + originalAlg + ") used - Vulnerable to key confusion attacks if expecting RSA", algSnippet));
            }
            
            // Weak algorithms with specific details
            String[] weakAlgorithms = {"hs1", "rs1", "es1", "ps1"};
            for (String weak : weakAlgorithms) {
                if (alg.contains(weak)) {
                    result.addFinding(new SecurityFinding("Algorithm", "high", 
                        "Weak algorithm detected: " + originalAlg + " - Uses deprecated SHA-1, upgrade to SHA-256 or higher", algSnippet));
                    break;
                }
            }
            
            // Check for standard algorithms
            String[] standardAlgorithms = {"hs256", "hs384", "hs512", "rs256", "rs384", "rs512", 
                                          "es256", "es384", "es512", "ps256", "ps384", "ps512"};
            boolean isStandard = false;
            for (String standard : standardAlgorithms) {
                if (standard.equals(alg)) {
                    isStandard = true;
                    break;
                }
            }
            if (!isStandard) {
                result.addFinding(new SecurityFinding("Algorithm", "medium", 
                    "Non-standard algorithm: " + originalAlg + " - May not be widely supported or secure", algSnippet));
            }
            
            // Good algorithms with specific recommendations
            if (alg.startsWith("rs")) {
                result.addFinding(new SecurityFinding("Algorithm", "info", 
                    "RSA algorithm (" + originalAlg + ") used - Good for distributed systems, ensure key size ≥ 2048 bits", algSnippet));
            } else if (alg.startsWith("es")) {
                result.addFinding(new SecurityFinding("Algorithm", "info", 
                    "ECDSA algorithm (" + originalAlg + ") used - Excellent performance and security", algSnippet));
            } else if (alg.startsWith("ps")) {
                result.addFinding(new SecurityFinding("Algorithm", "info", 
                    "PSS algorithm (" + originalAlg + ") used - Most secure RSA variant", algSnippet));
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error analyzing algorithm vulnerabilities: " + e.getMessage());
        }
    }
    
    private void analyzeSignatureIssues(String headerJson, SecurityAnalysisResult result) {
        try {
            // This would normally analyze the actual signature, but we only have header/payload
            // We can still check for algorithm-related signature issues
            String alg = extractJsonValue(headerJson, "alg");
            if (alg != null && "none".equals(alg.toLowerCase())) {
                result.addFinding(new SecurityFinding("Signature", "critical", 
                    "Missing signature - Token can be tampered with!"));
            }
        } catch (Exception e) {
            api.logging().logToError("Error analyzing signature: " + e.getMessage());
        }
    }
    
    private void analyzePayloadSecurity(String payloadJson, SecurityAnalysisResult result) {
        try {
            // XSS detection with specific details and snippets
            List<String> xssVectors = new ArrayList<>();
            String xssSnippet = "";
            for (Pattern pattern : XSS_PATTERNS) {
                Matcher matcher = pattern.matcher(payloadJson);
                if (matcher.find()) {
                    String found = matcher.group();
                    if (found.length() > 50) {
                        found = found.substring(0, 50) + "...";
                    }
                    xssVectors.add(found);
                    if (xssSnippet.isEmpty()) {
                        // Get context around the match
                        int start = Math.max(0, matcher.start() - 20);
                        int end = Math.min(payloadJson.length(), matcher.end() + 20);
                        xssSnippet = payloadJson.substring(start, end);
                    }
                }
            }
            if (!xssVectors.isEmpty()) {
                result.addFinding(new SecurityFinding("XSS", "high", 
                    "Potential XSS vectors detected: " + String.join(", ", xssVectors), xssSnippet));
            }
            
            // SQL Injection detection with specific details and snippets
            List<String> sqlPatterns = new ArrayList<>();
            String sqlSnippet = "";
            for (Pattern pattern : SQL_PATTERNS) {
                Matcher matcher = pattern.matcher(payloadJson);
                if (matcher.find()) {
                    String found = matcher.group();
                    if (found.length() > 30) {
                        found = found.substring(0, 30) + "...";
                    }
                    sqlPatterns.add(found);
                    if (sqlSnippet.isEmpty()) {
                        // Get context around the match
                        int start = Math.max(0, matcher.start() - 15);
                        int end = Math.min(payloadJson.length(), matcher.end() + 15);
                        sqlSnippet = payloadJson.substring(start, end);
                    }
                }
            }
            if (!sqlPatterns.isEmpty()) {
                result.addFinding(new SecurityFinding("SQL Injection", "high", 
                    "Potential SQL injection patterns detected: " + String.join(", ", sqlPatterns), sqlSnippet));
            }
            
            // Check for sensitive field names with snippets
            String[] sensitiveFields = {"password", "secret", "api_key", "apikey", "private_key", "privatekey", 
                                       "ssn", "social_security", "credit_card", "creditcard", "bank_account", 
                                       "drivers_license", "passport", "medical_id", "tax_id"};
            
            Map<String, String> fieldValues = extractFieldValues(payloadJson);
            for (String field : sensitiveFields) {
                if (containsField(payloadJson, field)) {
                    String severity = "critical";
                    if (field.contains("password") || field.contains("secret") || field.contains("key")) {
                        severity = "critical";
                    } else if (field.contains("credit") || field.equals("ssn") || field.contains("bank")) {
                        severity = "critical";
                    } else {
                        severity = "high";
                    }
                    
                    // Find the actual field and value for snippet
                    String snippet = "\"" + field + "\":\"...\"";
                    for (Map.Entry<String, String> entry : fieldValues.entrySet()) {
                        if (entry.getKey().toLowerCase().contains(field.toLowerCase())) {
                            snippet = "\"" + entry.getKey() + "\":\"" + entry.getValue() + "\"";
                            break;
                        }
                    }
                    
                    result.addFinding(new SecurityFinding("Data Exposure", severity, 
                        "Sensitive field \"" + field + "\" found in token payload", snippet));
                }
            }
            
            // Check for internal system information with specific details and snippets
            String[] internalPatterns = {"internal", "debug", "stacktrace", "error_details", "trace_id"};
            List<String> foundInternalInfo = new ArrayList<>();
            String internalSnippet = "";
            for (String pattern : internalPatterns) {
                if (payloadJson.toLowerCase().contains(pattern.toLowerCase())) {
                    foundInternalInfo.add(pattern);
                    if (internalSnippet.isEmpty()) {
                        // Find the context of the internal information
                        int index = payloadJson.toLowerCase().indexOf(pattern.toLowerCase());
                        if (index != -1) {
                            int start = Math.max(0, index - 15);
                            int end = Math.min(payloadJson.length(), index + pattern.length() + 15);
                            internalSnippet = payloadJson.substring(start, end);
                        }
                    }
                }
            }
            if (!foundInternalInfo.isEmpty()) {
                result.addFinding(new SecurityFinding("Data Exposure", "medium", 
                    "Internal system information detected: " + String.join(", ", foundInternalInfo), internalSnippet));
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error analyzing payload security: " + e.getMessage());
        }
    }
    
    private void analyzeTimeBasedAttacks(String payloadJson, SecurityAnalysisResult result) {
        try {
            long currentTime = System.currentTimeMillis() / 1000;
            
            // Check expiration
            String expStr = extractJsonValue(payloadJson, "exp");
            if (expStr != null) {
                String expSnippet = "\"exp\":" + expStr;
                try {
                    long exp = Long.parseLong(expStr);
                    if (exp < currentTime) {
                        long expiredSeconds = currentTime - exp;
                        result.addFinding(new SecurityFinding("Expiration", "high", 
                            "Token is expired (expired " + formatTimeAgo(expiredSeconds) + " ago)", expSnippet));
                    } else if (exp > currentTime + 365 * 24 * 60 * 60) {
                        result.addFinding(new SecurityFinding("Expiration", "medium", 
                            "Token has very long expiration (> 1 year)", expSnippet));
                    }
                } catch (NumberFormatException e) {
                    result.addFinding(new SecurityFinding("Expiration", "medium", 
                        "Invalid expiration format", expSnippet));
                }
            } else {
                result.addFinding(new SecurityFinding("Expiration", "high", 
                    "Token has no expiration claim (exp) - Never expires!"));
            }
            
            // Check issued at time
            String iatStr = extractJsonValue(payloadJson, "iat");
            if (iatStr != null) {
                String iatSnippet = "\"iat\":" + iatStr;
                try {
                    long iat = Long.parseLong(iatStr);
                    if (iat > currentTime) {
                        result.addFinding(new SecurityFinding("Time Validation", "high", 
                            "Token issued in the future - Possible clock skew or tampering", iatSnippet));
                    }
                } catch (NumberFormatException e) {
                    result.addFinding(new SecurityFinding("Time Validation", "medium", 
                        "Invalid issued at time format", iatSnippet));
                }
            } else {
                result.addFinding(new SecurityFinding("Time Validation", "low", 
                    "Token missing issued at (iat) claim"));
            }
            
            // Check not before time
            String nbfStr = extractJsonValue(payloadJson, "nbf");
            if (nbfStr != null) {
                String nbfSnippet = "\"nbf\":" + nbfStr;
                try {
                    long nbf = Long.parseLong(nbfStr);
                    if (nbf > currentTime) {
                        result.addFinding(new SecurityFinding("Time Validation", "medium", 
                            "Token not yet valid (nbf claim)", nbfSnippet));
                    }
                } catch (NumberFormatException e) {
                    result.addFinding(new SecurityFinding("Time Validation", "medium", 
                        "Invalid not before time format", nbfSnippet));
                }
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error analyzing time-based attacks: " + e.getMessage());
        }
    }
    
    private void analyzeClaimValidation(String payloadJson, SecurityAnalysisResult result) {
        try {
            // Check required claims
            if (extractJsonValue(payloadJson, "iss") == null) {
                result.addFinding(new SecurityFinding("Claims", "medium", 
                    "Missing issuer (iss) claim - Cannot verify token source"));
            }
            
            if (extractJsonValue(payloadJson, "aud") == null) {
                result.addFinding(new SecurityFinding("Claims", "medium", 
                    "Missing audience (aud) claim - Token can be used on any service"));
            }
            
            if (extractJsonValue(payloadJson, "jti") == null) {
                result.addFinding(new SecurityFinding("Claims", "low", 
                    "Missing JWT ID (jti) - No replay attack protection"));
            }
            
            // Check for subject/user identifier
            if (extractJsonValue(payloadJson, "sub") == null && 
                extractJsonValue(payloadJson, "user_id") == null && 
                extractJsonValue(payloadJson, "userId") == null) {
                result.addFinding(new SecurityFinding("Claims", "low", 
                    "Missing subject/user identifier claim"));
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error analyzing claims: " + e.getMessage());
        }
    }
    
    private void analyzeSensitiveDataExposure(String payloadJson, SecurityAnalysisResult result) {
        try {
            // Enhanced PII detection with smarter field checking
            Map<String, String> fieldValues = extractFieldValues(payloadJson);
            
            for (Map.Entry<String, String> entry : fieldValues.entrySet()) {
                String fieldName = entry.getKey();
                String fieldValue = entry.getValue();
                
                // Skip common ID fields for phone number detection
                String[] idFields = {"sub", "id", "user_id", "userId", "account_id", "accountId", 
                                   "customer_id", "customerId", "iat", "exp", "nbf"};
                boolean isIdField = false;
                for (String idField : idFields) {
                    if (fieldName.equals(idField)) {
                        isIdField = true;
                        break;
                    }
                }
                
                // Email detection
                if (EMAIL_PATTERN.matcher(fieldValue).find()) {
                    String snippet = "\"" + fieldName + "\":\"" + fieldValue + "\"";
                    result.addFinding(new SecurityFinding("Data Exposure", "high", 
                        "Email PII detected in field \"" + fieldName + "\"", snippet));
                }
                
                // Phone number detection (skip ID fields)
                if (!isIdField && PHONE_PATTERN.matcher(fieldValue).find()) {
                    String snippet = "\"" + fieldName + "\":\"" + fieldValue + "\"";
                    result.addFinding(new SecurityFinding("Data Exposure", "high", 
                        "Potential phone number detected in field \"" + fieldName + "\"", snippet));
                }
                
                // SSN detection
                if (SSN_PATTERN.matcher(fieldValue).find()) {
                    String snippet = "\"" + fieldName + "\":\"" + fieldValue + "\"";
                    result.addFinding(new SecurityFinding("Data Exposure", "critical", 
                        "SSN PII detected in field \"" + fieldName + "\"", snippet));
                }
                
                // Credit card detection
                if (CREDIT_CARD_PATTERN.matcher(fieldValue).find()) {
                    String snippet = "\"" + fieldName + "\":\"" + fieldValue + "\"";
                    result.addFinding(new SecurityFinding("Data Exposure", "critical", 
                        "Potential credit card number detected in field \"" + fieldName + "\"", snippet));
                }
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error analyzing sensitive data exposure: " + e.getMessage());
        }
    }
    
    private void analyzeInjectionVulnerabilities(String payloadJson, SecurityAnalysisResult result) {
        try {
            // LDAP Injection with specific characters
            Pattern ldapPattern = Pattern.compile("[*()\\\\|&]");
            Matcher ldapMatcher = ldapPattern.matcher(payloadJson);
            List<String> ldapChars = new ArrayList<>();
            while (ldapMatcher.find()) {
                String found = ldapMatcher.group();
                if (!ldapChars.contains(found)) {
                    ldapChars.add(found);
                }
            }
            if (!ldapChars.isEmpty()) {
                result.addFinding(new SecurityFinding("LDAP Injection", "medium", 
                    "LDAP injection characters detected: " + String.join(", ", ldapChars)));
            }
            
            // Command Injection with specific characters
            Pattern cmdPattern = Pattern.compile("[;&|`$()]");
            Matcher cmdMatcher = cmdPattern.matcher(payloadJson);
            List<String> cmdChars = new ArrayList<>();
            while (cmdMatcher.find()) {
                String found = cmdMatcher.group();
                if (!cmdChars.contains(found)) {
                    cmdChars.add(found);
                }
            }
            if (!cmdChars.isEmpty()) {
                result.addFinding(new SecurityFinding("Command Injection", "medium", 
                    "Command injection characters detected: " + String.join(", ", cmdChars)));
            }
            
            // NoSQL Injection with specific operators
            List<String> nosqlOperators = new ArrayList<>();
            String[] mongoOperators = {"$where", "$ne", "$gt", "$lt", "$regex", "$or", "$and", "$in", "$nin"};
            for (String operator : mongoOperators) {
                if (payloadJson.contains(operator)) {
                    nosqlOperators.add(operator);
                }
            }
            if (!nosqlOperators.isEmpty()) {
                result.addFinding(new SecurityFinding("NoSQL Injection", "medium", 
                    "NoSQL operators detected: " + String.join(", ", nosqlOperators)));
            } else if (payloadJson.contains("$") && (payloadJson.contains("{") || payloadJson.contains("["))) {
                result.addFinding(new SecurityFinding("NoSQL Injection", "medium", 
                    "Potential NoSQL injection pattern detected ($ with object notation)"));
            }
            
            // Path Traversal
            String[] pathTraversalPatterns = {"../", "..\\\\\\\\.", "....//", "%2e%2e%2f", "%2e%2e%5c"};
            List<String> foundTraversalPatterns = new ArrayList<>();
            for (String pattern : pathTraversalPatterns) {
                if (payloadJson.toLowerCase().contains(pattern.toLowerCase())) {
                    foundTraversalPatterns.add(pattern);
                }
            }
            if (!foundTraversalPatterns.isEmpty()) {
                result.addFinding(new SecurityFinding("Path Traversal", "medium", 
                    "Path traversal patterns detected: " + String.join(", ", foundTraversalPatterns)));
            }
            
            // XML/XXE patterns
            String[] xmlPatterns = {"<!DOCTYPE", "<!ENTITY", "SYSTEM", "PUBLIC"};
            List<String> foundXmlPatterns = new ArrayList<>();
            for (String pattern : xmlPatterns) {
                if (payloadJson.toUpperCase().contains(pattern.toUpperCase())) {
                    foundXmlPatterns.add(pattern);
                }
            }
            if (!foundXmlPatterns.isEmpty()) {
                result.addFinding(new SecurityFinding("XXE Injection", "high", 
                    "XML/XXE patterns detected: " + String.join(", ", foundXmlPatterns)));
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error analyzing injection vulnerabilities: " + e.getMessage());
        }
    }
    
    // Helper methods
    
    private String formatTimeAgo(long seconds) {
        if (seconds < 60) {
            return seconds + " seconds";
        } else if (seconds < 3600) {
            long minutes = seconds / 60;
            return minutes + " minute" + (minutes > 1 ? "s" : "");
        } else if (seconds < 86400) {
            long hours = seconds / 3600;
            return hours + " hour" + (hours > 1 ? "s" : "");
        } else if (seconds < 2592000) {
            long days = seconds / 86400;
            return days + " day" + (days > 1 ? "s" : "");
        } else if (seconds < 31536000) {
            long months = seconds / 2592000;
            return months + " month" + (months > 1 ? "s" : "");
        } else {
            long years = seconds / 31536000;
            return years + " year" + (years > 1 ? "s" : "");
        }
    }
    
    private Map<String, String> extractFieldValues(String json) {
        Map<String, String> fieldValues = new HashMap<>();
        try {
            // Simple JSON field extraction - looking for "field":"value" patterns
            Pattern fieldPattern = Pattern.compile("\"([^\"]+)\":\"([^\"]*)\"");
            Matcher matcher = fieldPattern.matcher(json);
            while (matcher.find()) {
                fieldValues.put(matcher.group(1), matcher.group(2));
            }
        } catch (Exception e) {
            api.logging().logToError("Error extracting field values: " + e.getMessage());
        }
        return fieldValues;
    }
}
