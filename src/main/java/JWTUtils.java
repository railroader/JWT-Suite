import java.util.Base64;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import burp.api.montoya.MontoyaApi;

public class JWTUtils {
    
    // Static API reference for logging - set by SessionManagement
    private static MontoyaApi api = null;
    
    public static void setApi(MontoyaApi montoyaApi) {
        api = montoyaApi;
    }
    
    private static void log(String message) {
        if (api != null) {
            api.logging().logToOutput("[JWTUtils] " + message);
        } else {
            System.out.println("[JWTUtils] " + message);
        }
    }
    
    private static void logError(String message) {
        if (api != null) {
            api.logging().logToError("[JWTUtils] " + message);
        } else {
            System.err.println("[JWTUtils] " + message);
        }
    }
    
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final DateTimeFormatter DATETIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    /**
     * Parse JWT token and extract expiration time
     * @param jwt JWT token string
     * @return Formatted expiration time or status
     */
    public static String getExpirationTime(String jwt) {
        if (jwt == null || jwt.trim().isEmpty()) {
            return "N/A";
        }
        
        try {
            // Clean the JWT token (remove Bearer prefix if present)
            String cleanJwt = jwt.trim();
            if (cleanJwt.startsWith("Bearer ")) {
                cleanJwt = cleanJwt.substring(7);
            }
            if (cleanJwt.startsWith("JWT ")) {
                cleanJwt = cleanJwt.substring(4);
            }
            
            log("Parsing JWT: " + cleanJwt.substring(0, Math.min(50, cleanJwt.length())) + "...");
            
            // Split JWT into parts
            String[] parts = cleanJwt.split("\\.");
            if (parts.length < 2) {
                logError("Invalid JWT format - expected 3 parts, got: " + parts.length);
                return "Invalid JWT";
            }
            
            // Decode payload (second part)
            String payload = parts[1];
            
            // Add Base64 padding if needed
            while (payload.length() % 4 != 0) {
                payload += "=";
            }
            
            log("Payload before decoding: " + payload.substring(0, Math.min(50, payload.length())));
            
            // Decode Base64
            byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
            String decodedPayload = new String(decodedBytes);
            
            log("Decoded payload: " + decodedPayload);
            
            // Extract expiration timestamp
            Long expTimestamp = extractExpTimestamp(decodedPayload);
            
            if (expTimestamp != null) {
                log("Found exp timestamp: " + expTimestamp);
                return formatExpirationTime(expTimestamp);
            } else {
                log("No expiration timestamp found - checking if token has any time fields");
                
                // Check if token has other time fields but no exp
                if (hasTimeFields(decodedPayload)) {
                    return "No Expiry Set";
                } else {
                    return "No Time Fields";
                }
            }
            
        } catch (IllegalArgumentException e) {
            logError("Base64 decode error: " + e.getMessage());
            // Try with standard decoder instead of URL decoder
            try {
                String cleanJwt = jwt.trim();
                if (cleanJwt.startsWith("Bearer ")) {
                    cleanJwt = cleanJwt.substring(7);
                }
                
                String[] parts = cleanJwt.split("\\.");
                if (parts.length >= 2) {
                    String payload = parts[1];
                    while (payload.length() % 4 != 0) {
                        payload += "=";
                    }
                    
                    byte[] decodedBytes = Base64.getDecoder().decode(payload);
                    String decodedPayload = new String(decodedBytes);
                    
                    log("Decoded payload (standard decoder): " + decodedPayload);
                    
                    Long expTimestamp = extractExpTimestamp(decodedPayload);
                    if (expTimestamp != null) {
                        return formatExpirationTime(expTimestamp);
                    }
                }
            } catch (Exception e2) {
                logError("Standard decoder also failed: " + e2.getMessage());
            }
            return "Decode Error: " + e.getMessage();
        } catch (Exception e) {
            logError("Error parsing JWT: " + e.getMessage());
            e.printStackTrace();
            return "Parse Error: " + e.getMessage();
        }
    }
    
    /**
     * Check if JWT payload has any time-related fields
     * @param payload Decoded JWT payload
     * @return true if has time fields like iat, nbf, etc.
     */
    private static boolean hasTimeFields(String payload) {
        // Common JWT time fields
        String[] timeFields = {"iat", "nbf", "exp", "auth_time", "updated_at"};
        
        for (String field : timeFields) {
            if (payload.contains("\"" + field + "\"") || payload.contains(field + ":")) {
                log("Found time field: " + field);
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Extract expiration timestamp from JWT payload
     * @param payload Decoded JWT payload JSON
     * @return Expiration timestamp or null if not found
     */
    private static Long extractExpTimestamp(String payload) {
        // Method 1: Look for "exp": followed by number
        Long timestamp = extractWithQuotes(payload);
        if (timestamp != null) {
            log("Found exp with quotes: " + timestamp);
            return timestamp;
        }
        
        // Method 2: Look for exp: without quotes
        timestamp = extractWithoutQuotes(payload);
        if (timestamp != null) {
            log("Found exp without quotes: " + timestamp);
            return timestamp;
        }
        
        // Method 3: Regex approach
        timestamp = extractWithRegex(payload);
        if (timestamp != null) {
            log("Found exp with regex: " + timestamp);
            return timestamp;
        }
        
        log("No exp field found in payload");
        return null;
    }
    
    /**
     * Extract exp value using "exp": pattern
     */
    private static Long extractWithQuotes(String payload) {
        try {
            String pattern = "\"exp\"";
            int expStart = payload.indexOf(pattern);
            if (expStart == -1) {
                return null;
            }
            
            int colonIndex = payload.indexOf(":", expStart);
            if (colonIndex == -1) {
                return null;
            }
            
            int valueStart = colonIndex + 1;
            
            // Skip whitespace and quotes
            while (valueStart < payload.length()) {
                char c = payload.charAt(valueStart);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '"') {
                    break;
                }
                valueStart++;
            }
            
            // Find end of number
            int valueEnd = valueStart;
            while (valueEnd < payload.length()) {
                char c = payload.charAt(valueEnd);
                if (!Character.isDigit(c)) {
                    break;
                }
                valueEnd++;
            }
            
            if (valueEnd > valueStart) {
                String expValue = payload.substring(valueStart, valueEnd);
                return Long.parseLong(expValue);
            }
        } catch (Exception e) {
            logError("Error in extractWithQuotes: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Extract exp value using exp: pattern (without quotes)
     */
    private static Long extractWithoutQuotes(String payload) {
        try {
            String pattern = "exp:";
            int expStart = payload.indexOf(pattern);
            if (expStart == -1) {
                return null;
            }
            
            int valueStart = expStart + pattern.length();
            
            // Skip whitespace
            while (valueStart < payload.length() && Character.isWhitespace(payload.charAt(valueStart))) {
                valueStart++;
            }
            
            // Find end of number
            int valueEnd = valueStart;
            while (valueEnd < payload.length() && Character.isDigit(payload.charAt(valueEnd))) {
                valueEnd++;
            }
            
            if (valueEnd > valueStart) {
                String expValue = payload.substring(valueStart, valueEnd);
                return Long.parseLong(expValue);
            }
        } catch (Exception e) {
            logError("Error in extractWithoutQuotes: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Extract exp value using regex pattern
     */
    private static Long extractWithRegex(String payload) {
        try {
            // Look for exp followed by colon and number
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"?exp\"?\\s*:\\s*(\\d+)");
            java.util.regex.Matcher matcher = pattern.matcher(payload);
            
            if (matcher.find()) {
                String expValue = matcher.group(1);
                return Long.parseLong(expValue);
            }
        } catch (Exception e) {
            logError("Error in extractWithRegex: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Format expiration timestamp into readable format
     * @param timestamp Unix timestamp
     * @return Formatted time string
     */
    private static String formatExpirationTime(long timestamp) {
        try {
            // Convert Unix timestamp to LocalDateTime
            Instant instant = Instant.ofEpochSecond(timestamp);
            LocalDateTime expDateTime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
            LocalDateTime now = LocalDateTime.now();
            
            log("Token expires at: " + expDateTime);
            log("Current time: " + now);
            
            // Add detailed expiration analysis
            if (expDateTime.isBefore(now)) {
                log("TOKEN IS EXPIRED by " + java.time.Duration.between(expDateTime, now).getSeconds() + " seconds");
            } else if (expDateTime.isBefore(now.plusMinutes(5))) {
                log("TOKEN EXPIRES SOON in " + java.time.Duration.between(now, expDateTime).getSeconds() + " seconds");
            } else {
                log("TOKEN IS VALID, expires in " + java.time.Duration.between(now, expDateTime).getSeconds() + " seconds");
            }
            
            // Check if expired or expiring soon
            if (expDateTime.isBefore(now)) {
                return "EXPIRED";
            } else if (expDateTime.isBefore(now.plusMinutes(5))) {
                return "EXPIRES_SOON";
            } else {
                return TIME_FORMATTER.format(expDateTime);
            }
        } catch (Exception e) {
            logError("Error formatting time: " + e.getMessage());
            return "Format Error";
        }
    }
    
    /**
     * Get risk level based on expiration status
     * @param expirationTime Expiration time string
     * @return Risk level
     */
    public static String getExpirationRisk(String expirationTime) {
        if ("EXPIRED".equals(expirationTime)) {
            return "HIGH";
        } else if ("EXPIRES_SOON".equals(expirationTime)) {
            return "MEDIUM";
        } else if ("Parse Error".startsWith(expirationTime) || "Invalid JWT".equals(expirationTime)) {
            return "HIGH";
        } else if ("No Expiry Set".equals(expirationTime)) {
            return "MEDIUM"; // Token without expiry could be a security risk
        } else if ("No Time Fields".equals(expirationTime) || "N/A".equals(expirationTime)) {
            return "LOW";
        } else {
            return "LOW"; // Valid expiration time
        }
    }
    
    /**
     * Test method to validate JWT parsing
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        // Test with valid JWT (expires 2030)
        String validJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE4OTM0NTYwMDB9.Jwt4zMhOawqSlhXdZL9ZfL2rGjhfEhP0uLVQaPNc5Ro";
        
        // Test with expired JWT (expired 2018)
        String expiredJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkxMjJ9.MpRrso6j8Q7xqE74QQyakKFEKGEr3rLs3CsJKtIlYH8";
        
        System.out.println("=== JWT Utils Test ===");
        
        System.out.println("\\nTesting valid JWT:");
        String validResult = getExpirationTime(validJWT);
        System.out.println("Result: " + validResult);
        
        System.out.println("\\nTesting expired JWT:");
        String expiredResult = getExpirationTime(expiredJWT);
        System.out.println("Result: " + expiredResult);
    }
    
    /**
     * Verify JWT signature using HMAC with the provided secret key
     * @param jwt Complete JWT token
     * @param secretKey Secret key to verify signature
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifyJWTSignature(String jwt, String secretKey) {
        if (jwt == null || secretKey == null) {
            return false;
        }
        
        try {
            // Clean the JWT token
            String cleanJwt = jwt.trim();
            if (cleanJwt.startsWith("Bearer ")) {
                cleanJwt = cleanJwt.substring(7);
            }
            if (cleanJwt.startsWith("JWT ")) {
                cleanJwt = cleanJwt.substring(4);
            }
            
            // Split JWT into parts
            String[] parts = cleanJwt.split("\\.");
            if (parts.length != 3) {
                return false;
            }
            
            String header = parts[0];
            String payload = parts[1];
            String signature = parts[2];
            
            // Determine the algorithm from header
            String algorithm = extractAlgorithmFromHeader(header);
            if (algorithm == null) {
                return false;
            }
            
            // Only support HMAC algorithms for brute force
            if (!algorithm.startsWith("HS")) {
                return false; // RSA/ECDSA algorithms cannot be brute forced with secret keys
            }
            
            // Create the signature string (header + "." + payload)
            String signatureInput = header + "." + payload;
            
            // Calculate expected signature
            String expectedSignature = calculateHMACSignature(signatureInput, secretKey, algorithm);
            
            // Compare signatures (remove any padding for comparison)
            String actualSignature = signature.replaceAll("=", "");
            expectedSignature = expectedSignature.replaceAll("=", "");
            
            return actualSignature.equals(expectedSignature);
            
        } catch (Exception e) {
            // Any exception means invalid signature
            return false;
        }
    }
    
    /**
     * Extract algorithm from JWT header
     * @param header Base64 encoded JWT header
     * @return Algorithm string (e.g., "HS256") or null if not found
     */
    private static String extractAlgorithmFromHeader(String header) {
        try {
            // Add padding if needed
            while (header.length() % 4 != 0) {
                header += "=";
            }
            
            // Decode header
            byte[] decodedBytes = Base64.getUrlDecoder().decode(header);
            String decodedHeader = new String(decodedBytes);
            
            // Extract algorithm - look for "alg": pattern
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");
            java.util.regex.Matcher matcher = pattern.matcher(decodedHeader);
            
            if (matcher.find()) {
                return matcher.group(1);
            }
            
        } catch (Exception e) {
            // Ignore errors
        }
        
        return null;
    }
    
    /**
     * Calculate HMAC signature for JWT
     * @param data Data to sign (header.payload)
     * @param secretKey Secret key
     * @param algorithm Algorithm (HS256, HS384, HS512)
     * @return Base64 URL-encoded signature
     */
    public static String calculateHMACSignature(String data, String secretKey, String algorithm) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        
        String javaAlgorithm;
        switch (algorithm) {
            case "HS256":
                javaAlgorithm = "HmacSHA256";
                break;
            case "HS384":
                javaAlgorithm = "HmacSHA384";
                break;
            case "HS512":
                javaAlgorithm = "HmacSHA512";
                break;
            default:
                throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
        }
        
        Mac mac = Mac.getInstance(javaAlgorithm);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), javaAlgorithm);
        mac.init(keySpec);
        
        byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }
}