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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.Objects;

/**
 * Enhanced JWT utilities with comprehensive exception handling, thread safety, and memory management
 * Provides crypto operations, time handling, and validation with proper resource cleanup
 */
public class EnhancedJWTUtils {
    private static final JWTExtensionLogger logger = JWTExtensionLogger.getLogger(EnhancedJWTUtils.class);
    private static final JWTResourceTracker resourceTracker = new JWTResourceTracker();
    
    // Thread-safe formatters
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final DateTimeFormatter DATETIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    // Thread-safe cache for MAC instances
    private static final ConcurrentHashMap<String, Mac> MAC_CACHE = new ConcurrentHashMap<>();
    private static final ReentrantReadWriteLock CACHE_LOCK = new ReentrantReadWriteLock();
    
    // Algorithm mappings with validation
    private static final ConcurrentHashMap<String, String> ALGORITHM_MAPPING = new ConcurrentHashMap<>();
    static {
        ALGORITHM_MAPPING.put("HS256", "HmacSHA256");
        ALGORITHM_MAPPING.put("HS384", "HmacSHA384");
        ALGORITHM_MAPPING.put("HS512", "HmacSHA512");
    }
    
    // Constants for time-based validation
    private static final long CLOCK_SKEW_TOLERANCE_SECONDS = 300; // 5 minutes
    private static final long EXPIRY_WARNING_THRESHOLD_SECONDS = 300; // 5 minutes
    
    /**
     * Parse JWT token and extract expiration time with comprehensive error handling
     * @param jwt JWT token string
     * @return Formatted expiration time or status
     */
    public static String getExpirationTime(String jwt) {
        logger.logMethodEntry("getExpirationTime");
        
        if (jwt == null || jwt.trim().isEmpty()) {
            logger.warn("Received null or empty JWT token");
            return "N/A";
        }
        
        String operationId = "exp-parse-" + System.currentTimeMillis();
        
        try {
            long startTime = System.currentTimeMillis();
            
            // Use the SafeJWTParser for enhanced parsing
            SafeJWTParser.ParsedJWTResult parsedResult = SafeJWTParser.parseJWTToken(jwt);
            if (parsedResult != null && parsedResult.isValid() && parsedResult.getComponents() != null) {
                Long expTime = parsedResult.getComponents().getExpirationTime().orElse(null);
                if (expTime != null) {
                    String result = formatExpirationTime(expTime);
                    logger.logPerformanceMetric("JWT expiration parsing", System.currentTimeMillis() - startTime);
                    return result;
                }
            }
            
            // Fallback to legacy parsing if new parser fails
            logger.debug("Falling back to legacy JWT parsing");
            return legacyGetExpirationTime(jwt);
            
        } catch (Exception e) {
            logger.error("Failed to parse JWT expiration time", e);
            return "Parse Error: " + e.getMessage();
        } finally {
            resourceTracker.releaseResource(operationId);
            logger.logMethodExit("getExpirationTime");
        }
    }
    
    /**
     * Legacy JWT expiration parsing (kept for compatibility)
     */
    private static String legacyGetExpirationTime(String jwt) {
        try {
            // Clean the JWT token (remove Bearer prefix if present)
            String cleanJwt = cleanToken(jwt);
            
            logger.debug("Parsing JWT: %s...", cleanJwt.substring(0, Math.min(50, cleanJwt.length())));
            
            // Split JWT into parts
            String[] parts = cleanJwt.split("\\.");
            if (parts.length < 2) {
                logger.error("Invalid JWT format - expected 3 parts, got: %d", parts.length);
                return "Invalid JWT";
            }
            
            // Decode payload (second part)
            String payload = parts[1];
            String decodedPayload = decodeBase64URLSafe(payload);
            
            logger.debug("Decoded payload: %s", decodedPayload);
            
            // Extract expiration timestamp
            Long expTimestamp = extractExpTimestamp(decodedPayload);
            
            if (expTimestamp != null) {
                logger.debug("Found exp timestamp: %d", expTimestamp);
                return formatExpirationTime(expTimestamp);
            } else {
                logger.debug("No expiration timestamp found");
                
                // Check if token has other time fields but no exp
                if (hasTimeFields(decodedPayload)) {
                    return "No Expiry Set";
                } else {
                    return "No Time Fields";
                }
            }
            
        } catch (JWTExtensionException e) {
            logger.error("JWT parsing error: %s", e.getDetailedMessage());
            return "Decode Error: " + e.getMessage();
        } catch (Exception e) {
            logger.error("Unexpected error parsing JWT", e);
            return "Parse Error: " + e.getMessage();
        }
    }
    
    /**
     * Safe Base64URL decoding with proper padding and error handling
     */
    private static String decodeBase64URLSafe(String encoded) throws JWTExtensionException {
        if (encoded == null || encoded.isEmpty()) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, "Cannot decode null or empty string");
        }
        
        String operationId = "base64-decode-" + System.currentTimeMillis();
        
        try {
            // Add Base64 padding if needed
            String padded = encoded;
            int padding = (4 - (encoded.length() % 4)) % 4;
            for (int i = 0; i < padding; i++) {
                padded += "=";
            }
            
            logger.trace("Decoding Base64URL: %s", padded.substring(0, Math.min(50, padded.length())));
            
            // Try URL decoder first
            try {
                byte[] decodedBytes = Base64.getUrlDecoder().decode(padded);
                String result = new String(decodedBytes, StandardCharsets.UTF_8);
                
                // Register for cleanup if contains sensitive data
                if (result.contains("password") || result.contains("secret") || result.contains("key")) {
                    String sensitiveId = resourceTracker.trackResource("sensitive-data");
                    logger.trace("Tracked sensitive JWT data: %s", sensitiveId);
                }
                
                return result;
            } catch (IllegalArgumentException e) {
                // Try standard decoder as fallback
                logger.debug("URL decoder failed, trying standard decoder");
                byte[] decodedBytes = Base64.getDecoder().decode(padded);
                return new String(decodedBytes, StandardCharsets.UTF_8);
            }
            
        } catch (IllegalArgumentException e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, 
                "Failed to decode Base64URL: " + e.getMessage(), "Input: " + encoded);
        } catch (Exception e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, 
                "Unexpected error during Base64URL decoding", "Input: " + encoded);
        }
    }
    
    /**
     * Clean JWT token by removing prefixes and whitespace
     */
    private static String cleanToken(String token) {
        if (token == null) return "";
        
        String clean = token.trim();
        
        if (clean.startsWith("Bearer ")) {
            clean = clean.substring(7).trim();
        } else if (clean.startsWith("JWT ")) {
            clean = clean.substring(4).trim();
        }
        
        return clean;
    }
    
    /**
     * Check if JWT payload has any time-related fields
     */
    private static boolean hasTimeFields(String payload) {
        if (payload == null || payload.isEmpty()) {
            return false;
        }
        
        // Common JWT time fields
        String[] timeFields = {"iat", "nbf", "exp", "auth_time", "updated_at"};
        
        for (String field : timeFields) {
            if (payload.contains("\"" + field + "\"") || payload.contains(field + ":")) {
                logger.trace("Found time field: %s", field);
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Extract expiration timestamp from JWT payload with multiple parsing strategies
     */
    private static Long extractExpTimestamp(String payload) {
        if (payload == null || payload.isEmpty()) {
            return null;
        }
        
        // Strategy 1: Look for "exp": followed by number
        Long timestamp = extractWithQuotes(payload);
        if (timestamp != null) {
            logger.trace("Found exp with quotes: %d", timestamp);
            return timestamp;
        }
        
        // Strategy 2: Look for exp: without quotes
        timestamp = extractWithoutQuotes(payload);
        if (timestamp != null) {
            logger.trace("Found exp without quotes: %d", timestamp);
            return timestamp;
        }
        
        // Strategy 3: Regex approach
        timestamp = extractWithRegex(payload);
        if (timestamp != null) {
            logger.trace("Found exp with regex: %d", timestamp);
            return timestamp;
        }
        
        logger.trace("No exp field found in payload");
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
        } catch (NumberFormatException e) {
            logger.debug("Failed to parse exp value as number: %s", e.getMessage());
        } catch (Exception e) {
            logger.debug("Error in extractWithQuotes: %s", e.getMessage());
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
        } catch (NumberFormatException e) {
            logger.debug("Failed to parse exp value as number: %s", e.getMessage());
        } catch (Exception e) {
            logger.debug("Error in extractWithoutQuotes: %s", e.getMessage());
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
        } catch (NumberFormatException e) {
            logger.debug("Failed to parse regex-extracted exp value: %s", e.getMessage());
        } catch (Exception e) {
            logger.debug("Error in extractWithRegex: %s", e.getMessage());
        }
        return null;
    }
    
    /**
     * Format expiration timestamp into readable format with enhanced time logic
     */
    private static String formatExpirationTime(long timestamp) {
        try {
            // Convert Unix timestamp to LocalDateTime
            Instant instant = Instant.ofEpochSecond(timestamp);
            LocalDateTime expDateTime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
            LocalDateTime now = LocalDateTime.now();
            
            logger.trace("Token expires at: %s", expDateTime);
            logger.trace("Current time: %s", now);
            
            // Check if expired or expiring soon
            if (expDateTime.isBefore(now)) {
                return "EXPIRED";
            } else if (expDateTime.isBefore(now.plusSeconds(EXPIRY_WARNING_THRESHOLD_SECONDS))) {
                return "EXPIRES_SOON";
            } else {
                return TIME_FORMATTER.format(expDateTime);
            }
        } catch (Exception e) {
            logger.error("Error formatting expiration time: %s", e.getMessage());
            return "Format Error";
        }
    }
    
    /**
     * Get risk level based on expiration status
     */
    public static String getExpirationRisk(String expirationTime) {
        if (expirationTime == null) {
            return "UNKNOWN";
        }
        
        switch (expirationTime) {
            case "EXPIRED":
                return "HIGH";
            case "EXPIRES_SOON":
                return "MEDIUM";
            case "No Expiry Set":
                return "MEDIUM"; // Token without expiry could be a security risk
            case "No Time Fields":
            case "N/A":
                return "LOW";
            default:
                if (expirationTime.startsWith("Parse Error") || expirationTime.startsWith("Invalid JWT")) {
                    return "HIGH";
                }
                return "LOW"; // Valid expiration time
        }
    }
    
    /**
     * Enhanced JWT signature verification with proper cryptographic operations
     */
    public static boolean verifyJWTSignature(String jwt, String secretKey) throws JWTExtensionException {
        logger.logMethodEntry("verifyJWTSignature");
        
        if (jwt == null || secretKey == null) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.INVALID_SIGNATURE, 
                "JWT token and secret key cannot be null");
        }
        
        String operationId = "sig-verify-" + System.currentTimeMillis();
        
        try {
            long startTime = System.currentTimeMillis();
            
            // Clean the JWT token
            String cleanJwt = cleanToken(jwt);
            
            // Split JWT into parts
            String[] parts = cleanJwt.split("\\.");
            if (parts.length != 3) {
                throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, 
                    "JWT must have exactly 3 parts, found: " + parts.length);
            }
            
            String header = parts[0];
            String payload = parts[1];
            String signature = parts[2];
            
            // Determine the algorithm from header
            String algorithm = extractAlgorithmFromHeader(header);
            if (algorithm == null) {
                throw new JWTExtensionException(JWTExtensionException.ErrorType.ALGORITHM_NOT_SUPPORTED, 
                    "Cannot determine algorithm from JWT header");
            }
            
            // Only support HMAC algorithms for secret key verification
            if (!algorithm.startsWith("HS")) {
                throw new JWTExtensionException(JWTExtensionException.ErrorType.ALGORITHM_NOT_SUPPORTED, 
                    "Algorithm " + algorithm + " cannot be verified with secret keys");
            }
            
            // Create the signature string (header + "." + payload)
            String signatureInput = header + "." + payload;
            
            // Track sensitive data
            String sensitiveId = resourceTracker.trackResource("secret-key");
            
            // Calculate expected signature
            String expectedSignature = calculateHMACSignature(signatureInput, secretKey, algorithm);
            
            // Compare signatures (constant-time comparison for security)
            String actualSignature = signature.replaceAll("=", "");
            expectedSignature = expectedSignature.replaceAll("=", "");
            
            boolean isValid = constantTimeEquals(actualSignature, expectedSignature);
            
            logger.logCryptoOperation("JWT signature verification", algorithm);
            logger.logPerformanceMetric("JWT signature verification", System.currentTimeMillis() - startTime);
            
            return isValid;
            
        } catch (JWTExtensionException e) {
            throw e;
        } catch (Exception e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.CRYPTO_OPERATION_FAILED, 
                "Signature verification failed: " + e.getMessage());
        } finally {
            resourceTracker.releaseResource(operationId);
            logger.logMethodExit("verifyJWTSignature");
        }
    }
    
    /**
     * Constant-time string comparison to prevent timing attacks
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        if (a.length() != b.length()) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        
        return result == 0;
    }
    
    /**
     * Extract algorithm from JWT header with proper error handling
     */
    private static String extractAlgorithmFromHeader(String header) throws JWTExtensionException {
        try {
            String decodedHeader = decodeBase64URLSafe(header);
            
            // Extract algorithm - look for "alg": pattern
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");
            java.util.regex.Matcher matcher = pattern.matcher(decodedHeader);
            
            if (matcher.find()) {
                return matcher.group(1);
            }
            
            return null;
            
        } catch (Exception e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, 
                "Failed to extract algorithm from header", "Header: " + header);
        }
    }
    
    /**
     * Enhanced HMAC signature calculation with caching and proper resource management
     */
    public static String calculateHMACSignature(String data, String secretKey, String algorithm) 
            throws JWTExtensionException {
        
        logger.logMethodEntry("calculateHMACSignature");
        
        if (data == null || secretKey == null || algorithm == null) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.CRYPTO_OPERATION_FAILED, 
                "Data, secret key, and algorithm cannot be null");
        }
        
        String javaAlgorithm = ALGORITHM_MAPPING.get(algorithm);
        if (javaAlgorithm == null) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.ALGORITHM_NOT_SUPPORTED, 
                "Unsupported algorithm: " + algorithm);
        }
        
        String operationId = "hmac-calc-" + System.currentTimeMillis();
        
        try {
            long startTime = System.currentTimeMillis();
            
            // Get or create MAC instance (with caching for performance)
            Mac mac = getOrCreateMac(javaAlgorithm);
            
            // Create secret key spec
            byte[] secretBytes = secretKey.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(secretBytes, javaAlgorithm);
            
            // Synchronized MAC operations for thread safety
            byte[] signature;
            synchronized (mac) {
                mac.init(keySpec);
                signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            }
            
            String result = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            
            logger.logCryptoOperation("HMAC signature calculation", algorithm);
            logger.logPerformanceMetric("HMAC signature calculation", System.currentTimeMillis() - startTime);
            
            return result;
            
        } catch (NoSuchAlgorithmException e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.ALGORITHM_NOT_SUPPORTED, 
                "Algorithm not supported: " + javaAlgorithm);
        } catch (InvalidKeyException e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.CRYPTO_OPERATION_FAILED, 
                "Invalid secret key for algorithm: " + algorithm);
        } catch (Exception e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.CRYPTO_OPERATION_FAILED, 
                "HMAC calculation failed: " + e.getMessage());
        } finally {
            resourceTracker.releaseResource(operationId);
            logger.logMethodExit("calculateHMACSignature");
        }
    }
    
    /**
     * Get or create MAC instance with thread-safe caching
     */
    private static Mac getOrCreateMac(String algorithm) throws NoSuchAlgorithmException {
        // Try to get from cache first
        CACHE_LOCK.readLock().lock();
        try {
            Mac cached = MAC_CACHE.get(algorithm);
            if (cached != null) {
                return cached;
            }
        } finally {
            CACHE_LOCK.readLock().unlock();
        }
        
        // Create new MAC instance
        CACHE_LOCK.writeLock().lock();
        try {
            // Double-check pattern
            Mac cached = MAC_CACHE.get(algorithm);
            if (cached != null) {
                return cached;
            }
            
            Mac mac = Mac.getInstance(algorithm);
            MAC_CACHE.put(algorithm, mac);
            
            logger.debug("Created and cached MAC instance for algorithm: %s", algorithm);
            return mac;
            
        } finally {
            CACHE_LOCK.writeLock().unlock();
        }
    }
    
    /**
     * Get detailed JWT expiration information
     */
    public static JWTExpirationInfo getJWTExpirationInfo(String jwt) throws JWTExtensionException {
        logger.logMethodEntry("getJWTExpirationInfo");
        
        try {
            SafeJWTParser.ParsedJWTResult parsedResult = SafeJWTParser.parseJWTToken(jwt);
            
            if (!parsedResult.isValid() || parsedResult.getComponents() == null) {
                throw new JWTExtensionException(
                    JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED,
                    "Failed to parse JWT: " + parsedResult.getValidationSummary()
                );
            }
            
            long currentTime = System.currentTimeMillis() / 1000;
            Long expTime = parsedResult.getComponents().getExpirationTime().orElse(null);
            Long iatTime = null; // Not implemented in SafeJWTParser yet
            Long nbfTime = null; // Not implemented in SafeJWTParser yet
            
            boolean isExpired = expTime != null && currentTime > expTime;
            boolean isNotYetValid = nbfTime != null && currentTime < nbfTime;
            String formattedExp = expTime != null ? formatExpirationTime(expTime) : "No expiry";
            
            return new JWTExpirationInfo(
                expTime,
                iatTime,
                nbfTime,
                currentTime,
                isExpired,
                isNotYetValid,
                formattedExp
            );
            
        } catch (Exception e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, 
                "Failed to get JWT expiration info: " + e.getMessage());
        } finally {
            logger.logMethodExit("getJWTExpirationInfo");
        }
    }
    
    /**
     * Clear all caches and perform cleanup
     */
    public static void cleanup() {
        logger.info("Performing JWT utilities cleanup");
        
        CACHE_LOCK.writeLock().lock();
        try {
            MAC_CACHE.clear();
            logger.debug("Cleared MAC cache");
        } finally {
            CACHE_LOCK.writeLock().unlock();
        }
        
        SafeJWTParser.clearCache();
        logger.info("JWT utilities cleanup completed");
    }
    
    /**
     * Get cache statistics for monitoring
     */
    public static String getCacheStats() {
        CACHE_LOCK.readLock().lock();
        try {
            return String.format("EnhancedJWTUtils Cache Stats - MAC instances: %d, %s", 
                MAC_CACHE.size(), SafeJWTParser.getCacheStats());
        } finally {
            CACHE_LOCK.readLock().unlock();
        }
    }
    
    /**
     * JWT expiration information data class
     */
    public static class JWTExpirationInfo {
        public final Long expirationTime;
        public final Long issuedAt;
        public final Long notBefore;
        public final long currentTime;
        public final boolean isExpired;
        public final boolean isNotYetValid;
        public final String formattedExpiration;
        
        public JWTExpirationInfo(Long expirationTime, Long issuedAt, Long notBefore, 
                               long currentTime, boolean isExpired, boolean isNotYetValid, 
                               String formattedExpiration) {
            this.expirationTime = expirationTime;
            this.issuedAt = issuedAt;
            this.notBefore = notBefore;
            this.currentTime = currentTime;
            this.isExpired = isExpired;
            this.isNotYetValid = isNotYetValid;
            this.formattedExpiration = formattedExpiration;
        }
        
        public long getSecondsUntilExpiration() {
            return expirationTime != null ? expirationTime - currentTime : -1;
        }
        
        public long getSecondsUntilValid() {
            return notBefore != null ? notBefore - currentTime : 0;
        }
        
        public boolean isValidNow() {
            return !isExpired && !isNotYetValid;
        }
        
        @Override
        public String toString() {
            return String.format("JWTExpirationInfo{exp=%s, iat=%s, nbf=%s, expired=%s, notYetValid=%s}", 
                expirationTime, issuedAt, notBefore, isExpired, isNotYetValid);
        }
    }
    
    // Private constructor to prevent instantiation
    private EnhancedJWTUtils() {
        // Utility class - do not instantiate
    }
}
