import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe JWT token parser with improved validation and error recovery
 * Provides caching and comprehensive structure validation
 */
public class SafeJWTParser {
    private static final JWTExtensionLogger logger = JWTExtensionLogger.getLogger(SafeJWTParser.class);
    private static final JWTResourceTracker resourceTracker = new JWTResourceTracker();
    
    // Thread-safe cache for parsed tokens
    private static final Map<String, ParsedJWTResult> parseCache = new ConcurrentHashMap<>();
    private static final ReentrantReadWriteLock cacheLock = new ReentrantReadWriteLock();
    private static final int MAX_CACHE_SIZE = 500;
    
    // Token structure validation patterns
    private static final String JWT_PATTERN = "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$";
    private static final String BASE64_PATTERN = "^[A-Za-z0-9+/]*={0,2}$";
    private static final String BASE64URL_PATTERN = "^[A-Za-z0-9_-]*$";
    
    /**
     * Result of JWT parsing operation
     */
    public static class ParsedJWTResult {
        private final boolean isValid;
        private final String originalToken;
        private final JWTComponents components;
        private final List<String> validationErrors;
        private final long parseTimestamp;
        private final String parseId;
        
        public ParsedJWTResult(boolean isValid, String originalToken, JWTComponents components, 
                              List<String> validationErrors) {
            this.isValid = isValid;
            this.originalToken = originalToken;
            this.components = components;
            this.validationErrors = validationErrors != null ? 
                Collections.unmodifiableList(new ArrayList<>(validationErrors)) : 
                Collections.emptyList();
            this.parseTimestamp = System.currentTimeMillis();
            this.parseId = resourceTracker.trackResource("ParsedJWT");
        }
        
        public boolean isValid() { return isValid; }
        public String getOriginalToken() { return originalToken; }
        public JWTComponents getComponents() { return components; }
        public List<String> getValidationErrors() { return validationErrors; }
        public long getParseTimestamp() { return parseTimestamp; }
        public String getParseId() { return parseId; }
        
        public boolean hasValidationErrors() {
            return !validationErrors.isEmpty();
        }
        
        public String getValidationSummary() {
            if (validationErrors.isEmpty()) {
                return "No validation errors";
            }
            return String.format("%d validation errors: %s", 
                validationErrors.size(), String.join(", ", validationErrors));
        }
        
        // Cleanup method
        public void cleanup() {
            resourceTracker.releaseResource(parseId);
        }
    }
    
    /**
     * JWT token components
     */
    public static class JWTComponents {
        private final String header;
        private final String payload;
        private final String signature;
        private final Map<String, Object> headerClaims;
        private final Map<String, Object> payloadClaims;
        
        public JWTComponents(String header, String payload, String signature,
                           Map<String, Object> headerClaims, Map<String, Object> payloadClaims) {
            this.header = header;
            this.payload = payload;
            this.signature = signature;
            this.headerClaims = headerClaims != null ? 
                Collections.unmodifiableMap(new HashMap<>(headerClaims)) : 
                Collections.emptyMap();
            this.payloadClaims = payloadClaims != null ? 
                Collections.unmodifiableMap(new HashMap<>(payloadClaims)) : 
                Collections.emptyMap();
        }
        
        public String getHeader() { return header; }
        public String getPayload() { return payload; }
        public String getSignature() { return signature; }
        public Map<String, Object> getHeaderClaims() { return headerClaims; }
        public Map<String, Object> getPayloadClaims() { return payloadClaims; }
        
        public Optional<String> getAlgorithm() {
            Object alg = headerClaims.get("alg");
            return alg != null ? Optional.of(alg.toString()) : Optional.empty();
        }
        
        public Optional<Long> getExpirationTime() {
            Object exp = payloadClaims.get("exp");
            if (exp instanceof Number) {
                return Optional.of(((Number) exp).longValue());
            }
            return Optional.empty();
        }
        
        public Optional<String> getSubject() {
            Object sub = payloadClaims.get("sub");
            return sub != null ? Optional.of(sub.toString()) : Optional.empty();
        }
        
        public Optional<String> getIssuer() {
            Object iss = payloadClaims.get("iss");
            return iss != null ? Optional.of(iss.toString()) : Optional.empty();
        }
    }
    
    /**
     * Parse JWT token with comprehensive validation
     */
    public static ParsedJWTResult parseJWTToken(String token) {
        logger.logMethodEntry("parseJWTToken");
        long startTime = System.currentTimeMillis();
        
        if (token == null || token.trim().isEmpty()) {
            logger.warn("Received null or empty JWT token");
            return createErrorResult(token, Arrays.asList("Token is null or empty"));
        }
        
        try {
            // Clean the token
            String cleanToken = cleanJWTToken(token);
            
            // Check cache first
            ParsedJWTResult cached = getCachedResult(cleanToken);
            if (cached != null) {
                logger.debug("Retrieved JWT from cache");
                return cached;
            }
            
            // Perform parsing
            ParsedJWTResult result = performJWTParsing(cleanToken);
            
            // Cache the result
            cacheResult(cleanToken, result);
            
            logger.logPerformanceMetric("JWT parsing", System.currentTimeMillis() - startTime);
            return result;
            
        } catch (Exception e) {
            logger.error("Unexpected error during JWT parsing", e);
            return createErrorResult(token, Arrays.asList("Parsing failed: " + e.getMessage()));
        } finally {
            logger.logMethodExit("parseJWTToken");
        }
    }
    
    /**
     * Clean JWT token by removing prefixes
     */
    private static String cleanJWTToken(String token) {
        String clean = token.trim();
        
        if (clean.startsWith("Bearer ")) {
            clean = clean.substring(7).trim();
        } else if (clean.startsWith("JWT ")) {
            clean = clean.substring(4).trim();
        }
        
        return clean;
    }
    
    /**
     * Get cached parsing result
     */
    private static ParsedJWTResult getCachedResult(String token) {
        cacheLock.readLock().lock();
        try {
            return parseCache.get(token);
        } finally {
            cacheLock.readLock().unlock();
        }
    }
    
    /**
     * Cache parsing result with size management
     */
    private static void cacheResult(String token, ParsedJWTResult result) {
        cacheLock.writeLock().lock();
        try {
            if (parseCache.size() >= MAX_CACHE_SIZE) {
                // Remove oldest entries (simple strategy)
                Iterator<String> iterator = parseCache.keySet().iterator();
                int toRemove = parseCache.size() / 4; // Remove 25%
                for (int i = 0; i < toRemove && iterator.hasNext(); i++) {
                    String key = iterator.next();
                    ParsedJWTResult oldResult = parseCache.remove(key);
                    if (oldResult != null) {
                        oldResult.cleanup();
                    }
                }
                logger.debug("Cleaned JWT parse cache, removed %d entries", toRemove);
            }
            
            parseCache.put(token, result);
        } finally {
            cacheLock.writeLock().unlock();
        }
    }
    
    /**
     * Perform actual JWT parsing with validation
     */
    private static ParsedJWTResult performJWTParsing(String token) {
        List<String> errors = new ArrayList<>();
        
        // Validate basic JWT structure
        if (!token.matches(JWT_PATTERN)) {
            errors.add("Invalid JWT structure - must be three base64url parts separated by dots");
            return createErrorResult(token, errors);
        }
        
        // Split token into parts
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            errors.add("JWT must have exactly 3 parts, found: " + parts.length);
            return createErrorResult(token, errors);
        }
        
        String headerPart = parts[0];
        String payloadPart = parts[1];
        String signaturePart = parts[2];
        
        // Validate base64url encoding
        if (!isValidBase64URL(headerPart)) {
            errors.add("Header is not valid base64url encoded");
        }
        if (!isValidBase64URL(payloadPart)) {
            errors.add("Payload is not valid base64url encoded");
        }
        if (!isValidBase64URL(signaturePart) && !signaturePart.isEmpty()) {
            errors.add("Signature is not valid base64url encoded");
        }
        
        // Decode header and payload
        Map<String, Object> headerClaims = null;
        Map<String, Object> payloadClaims = null;
        
        try {
            String decodedHeader = decodeBase64URL(headerPart);
            headerClaims = parseJSONSimple(decodedHeader);
            logger.trace("Decoded header: %s", decodedHeader);
        } catch (Exception e) {
            errors.add("Failed to decode header: " + e.getMessage());
        }
        
        try {
            String decodedPayload = decodeBase64URL(payloadPart);
            payloadClaims = parseJSONSimple(decodedPayload);
            logger.trace("Decoded payload: %s", decodedPayload);
        } catch (Exception e) {
            errors.add("Failed to decode payload: " + e.getMessage());
        }
        
        // Validate required claims
        if (headerClaims != null) {
            validateHeaderClaims(headerClaims, errors);
        }
        
        if (payloadClaims != null) {
            validatePayloadClaims(payloadClaims, errors);
        }
        
        // Create components
        JWTComponents components = new JWTComponents(
            headerPart, payloadPart, signaturePart,
            headerClaims, payloadClaims
        );
        
        boolean isValid = errors.isEmpty();
        return new ParsedJWTResult(isValid, token, components, errors);
    }
    
    /**
     * Validate base64url encoding
     */
    private static boolean isValidBase64URL(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return input.matches(BASE64URL_PATTERN);
    }
    
    /**
     * Decode base64url string
     */
    private static String decodeBase64URL(String encoded) throws JWTExtensionException {
        try {
            // Add padding if necessary
            String padded = encoded;
            int padding = (4 - (encoded.length() % 4)) % 4;
            for (int i = 0; i < padding; i++) {
                padded += "=";
            }
            
            byte[] decoded = Base64.getUrlDecoder().decode(padded);
            return new String(decoded, "UTF-8");
        } catch (Exception e) {
            throw new JWTExtensionException(
                JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED,
                "Failed to decode base64url: " + e.getMessage(),
                "Input: " + encoded,
                e
            );
        }
    }
    
    /**
     * Simple JSON parser for JWT claims (basic implementation)
     */
    private static Map<String, Object> parseJSONSimple(String json) throws JWTExtensionException {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Remove outer braces
            String content = json.trim();
            if (!content.startsWith("{") || !content.endsWith("}")) {
                throw new JWTExtensionException(
                    JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED,
                    "Invalid JSON structure - must start with { and end with }"
                );
            }
            
            content = content.substring(1, content.length() - 1).trim();
            
            if (content.isEmpty()) {
                return result;
            }
            
            // Split by commas (simple parsing - doesn't handle nested objects)
            String[] pairs = content.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
            
            for (String pair : pairs) {
                String[] keyValue = pair.split(":", 2);
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim().replaceAll("^\"|\"$", "");
                    String value = keyValue[1].trim();
                    
                    Object parsedValue = parseJSONValue(value);
                    result.put(key, parsedValue);
                }
            }
            
            return result;
        } catch (Exception e) {
            throw new JWTExtensionException(
                JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED,
                "Failed to parse JSON: " + e.getMessage(),
                "JSON: " + json,
                e
            );
        }
    }
    
    /**
     * Parse individual JSON value
     */
    private static Object parseJSONValue(String value) {
        value = value.trim();
        
        if (value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        } else if ("true".equals(value)) {
            return Boolean.TRUE;
        } else if ("false".equals(value)) {
            return Boolean.FALSE;
        } else if ("null".equals(value)) {
            return null;
        } else {
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
    
    /**
     * Validate header claims
     */
    private static void validateHeaderClaims(Map<String, Object> headerClaims, List<String> errors) {
        // Check for required algorithm claim
        if (!headerClaims.containsKey("alg")) {
            errors.add("Header missing required 'alg' claim");
        } else {
            Object alg = headerClaims.get("alg");
            if (alg == null || alg.toString().isEmpty()) {
                errors.add("Algorithm claim 'alg' is empty");
            }
        }
        
        // Check for type claim if present
        if (headerClaims.containsKey("typ")) {
            Object typ = headerClaims.get("typ");
            if (typ != null && !"JWT".equalsIgnoreCase(typ.toString())) {
                errors.add("Unexpected token type: " + typ);
            }
        }
    }
    
    /**
     * Validate payload claims
     */
    private static void validatePayloadClaims(Map<String, Object> payloadClaims, List<String> errors) {
        long currentTime = System.currentTimeMillis() / 1000;
        
        // Check expiration time
        if (payloadClaims.containsKey("exp")) {
            Object exp = payloadClaims.get("exp");
            if (exp instanceof Number) {
                long expTime = ((Number) exp).longValue();
                if (expTime < currentTime) {
                    errors.add("Token has expired");
                }
            } else {
                errors.add("Expiration time 'exp' claim is not a number");
            }
        }
        
        // Check not before time
        if (payloadClaims.containsKey("nbf")) {
            Object nbf = payloadClaims.get("nbf");
            if (nbf instanceof Number) {
                long nbfTime = ((Number) nbf).longValue();
                if (nbfTime > currentTime) {
                    errors.add("Token is not yet valid");
                }
            } else {
                errors.add("Not before 'nbf' claim is not a number");
            }
        }
        
        // Check issued at time
        if (payloadClaims.containsKey("iat")) {
            Object iat = payloadClaims.get("iat");
            if (iat instanceof Number) {
                long iatTime = ((Number) iat).longValue();
                if (iatTime > currentTime + 300) { // 5 minute tolerance
                    errors.add("Token issued in the future");
                }
            } else {
                errors.add("Issued at 'iat' claim is not a number");
            }
        }
    }
    
    /**
     * Create error result
     */
    private static ParsedJWTResult createErrorResult(String token, List<String> errors) {
        return new ParsedJWTResult(false, token, null, errors);
    }
    
    /**
     * Check if token appears to be a JWT
     */
    public static boolean looksLikeJWT(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        
        String clean = cleanJWTToken(token);
        return clean.matches(JWT_PATTERN);
    }
    
    /**
     * Get cache statistics
     */
    public static String getCacheStats() {
        cacheLock.readLock().lock();
        try {
            return String.format("JWT Parse Cache: %d entries (max: %d)", 
                parseCache.size(), MAX_CACHE_SIZE);
        } finally {
            cacheLock.readLock().unlock();
        }
    }
    
    /**
     * Clear cache and cleanup resources
     */
    public static void clearCache() {
        cacheLock.writeLock().lock();
        try {
            for (ParsedJWTResult result : parseCache.values()) {
                result.cleanup();
            }
            parseCache.clear();
            logger.info("JWT parse cache cleared");
        } finally {
            cacheLock.writeLock().unlock();
        }
    }
}
