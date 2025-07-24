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

/**
 * Thread-safe, immutable JWT class with comprehensive parsing and validation
 * Inspired by jwt-scanner's architecture with enhanced error handling and memory management
 */
public final class ImmutableJWT {
    private static final JWTExtensionLogger logger = JWTExtensionLogger.getLogger(ImmutableJWT.class);
    private static final JWTResourceTracker resourceTracker = new JWTResourceTracker();
    
    // JWT structure validation pattern
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "^([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]*)$"
    );
    
    // Supported algorithms for validation
    private static final Set<String> SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList(
            "HS256", "HS384", "HS512",
            "RS256", "RS384", "RS512",
            "ES256", "ES384", "ES512",
            "PS256", "PS384", "PS512",
            "none"
        ))
    );
    
    // Cache for parsed tokens (thread-safe)
    private static final Map<String, ImmutableJWT> PARSE_CACHE = new ConcurrentHashMap<>();
    private static final int MAX_CACHE_SIZE = 1000;
    
    // Immutable fields
    private final String originalToken;
    private final String encodedHeader;
    private final String encodedPayload;
    private final String encodedSignature;
    private final Map<String, Object> header;
    private final Map<String, Object> payload;
    private final String algorithm;
    private final Long expirationTime;
    private final Long issuedAt;
    private final Long notBefore;
    private final boolean isValid;
    private final List<String> validationErrors;
    private final String tokenId; // Unique identifier for memory management
    
    /**
     * Private constructor to ensure immutability
     */
    private ImmutableJWT(Builder builder) throws JWTExtensionException {
        this.originalToken = builder.originalToken;
        this.encodedHeader = builder.encodedHeader;
        this.encodedPayload = builder.encodedPayload;
        this.encodedSignature = builder.encodedSignature;
        this.header = Collections.unmodifiableMap(new LinkedHashMap<>(builder.header));
        this.payload = Collections.unmodifiableMap(new LinkedHashMap<>(builder.payload));
        this.algorithm = builder.algorithm;
        this.expirationTime = builder.expirationTime;
        this.issuedAt = builder.issuedAt;
        this.notBefore = builder.notBefore;
        this.isValid = builder.isValid;
        this.validationErrors = Collections.unmodifiableList(new ArrayList<>(builder.validationErrors));
        this.tokenId = UUID.randomUUID().toString();
        
        // Register for resource tracking
        resourceTracker.trackResource("ImmutableJWT-" + this.tokenId);
        
        logger.trace("Created immutable JWT instance: %s", this.tokenId);
    }
    
    /**
     * Parse a JWT token string into an immutable JWT object
     */
    public static ImmutableJWT parse(String token) throws JWTExtensionException {
        if (token == null || token.trim().isEmpty()) {
            throw new JWTTokenParseException("Token cannot be null or empty", token);
        }
        
        // Clean the token
        String cleanToken = cleanToken(token);
        
        // Check cache first
        ImmutableJWT cached = PARSE_CACHE.get(cleanToken);
        if (cached != null) {
            logger.trace("Retrieved JWT from cache");
            return cached;
        }
        
        // Parse new token
        long startTime = System.currentTimeMillis();
        ImmutableJWT jwt = parseInternal(cleanToken);
        
        // Cache the result (with size limit)
        if (PARSE_CACHE.size() < MAX_CACHE_SIZE) {
            PARSE_CACHE.put(cleanToken, jwt);
        } else if (PARSE_CACHE.size() >= MAX_CACHE_SIZE) {
            // Clear cache when it gets too large
            PARSE_CACHE.clear();
            PARSE_CACHE.put(cleanToken, jwt);
            logger.debug("JWT parse cache cleared due to size limit");
        }
        
        logger.logPerformanceMetric("JWT parsing", System.currentTimeMillis() - startTime);
        return jwt;
    }
    
    /**
     * Try to parse a JWT token, returning null if parsing fails
     */
    public static ImmutableJWT tryParse(String token) {
        try {
            return parse(token);
        } catch (JWTExtensionException e) {
            logger.debug("JWT parsing failed: %s", e.getMessage());
            return null;
        }
    }
    
    /**
     * Internal parsing logic
     */
    private static ImmutableJWT parseInternal(String token) throws JWTExtensionException {
        logger.logMethodEntry("parseInternal");
        
        // Validate token structure
        Matcher matcher = JWT_PATTERN.matcher(token);
        if (!matcher.matches()) {
            throw new JWTTokenParseException("Invalid JWT structure", token);
        }
        
        String encodedHeader = matcher.group(1);
        String encodedPayload = matcher.group(2);
        String encodedSignature = matcher.group(3);
        
        Builder builder = new Builder()
            .withOriginalToken(token)
            .withEncodedParts(encodedHeader, encodedPayload, encodedSignature);
        
        try {
            // Parse header
            Map<String, Object> header = parseJsonSection(encodedHeader, "header");
            builder.withHeader(header);
            
            // Parse payload
            Map<String, Object> payload = parseJsonSection(encodedPayload, "payload");
            builder.withPayload(payload);
            
            // Extract common claims
            builder.extractCommonClaims();
            
            // Validate the token
            builder.validate();
            
            return new ImmutableJWT(builder);
            
        } catch (Exception e) {
            if (e instanceof JWTExtensionException) {
                throw (JWTExtensionException) e;
            }
            throw new JWTTokenParseException("Failed to parse JWT: " + e.getMessage(), token, e);
        }
    }
    
    /**
     * Parse a Base64URL encoded JSON section
     */
    private static Map<String, Object> parseJsonSection(String encoded, String sectionName) throws JWTExtensionException {
        try {
            String decoded = decodeBase64URL(encoded);
            return parseJson(decoded);
        } catch (Exception e) {
            throw new JWTTokenParseException("Failed to parse " + sectionName + " section", encoded, e);
        }
    }
    
    /**
     * Decode Base64URL with proper padding
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
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, 
                "Failed to decode Base64URL: " + e.getMessage());
        }
    }
    
    /**
     * Encode string to Base64URL without padding
     */
    private static String encodeBase64URL(String input) {
        byte[] encoded = Base64.getUrlEncoder().withoutPadding().encode(input.getBytes(StandardCharsets.UTF_8));
        return new String(encoded, StandardCharsets.UTF_8);
    }
    
    /**
     * Parse JSON string into a Map (simple implementation for JWT)
     */
    private static Map<String, Object> parseJson(String json) throws JWTExtensionException {
        // This is a simplified JSON parser for JWT purposes
        // In production, you might want to use a proper JSON library
        Map<String, Object> result = new LinkedHashMap<>();
        
        try {
            // Remove outer braces and whitespace
            String content = json.trim();
            if (!content.startsWith("{") || !content.endsWith("}")) {
                throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, "Invalid JSON structure");
            }
            
            content = content.substring(1, content.length() - 1).trim();
            
            if (content.isEmpty()) {
                return result;
            }
            
            // Split by commas (simple approach - doesn't handle nested objects perfectly)
            String[] pairs = content.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
            
            for (String pair : pairs) {
                String[] keyValue = pair.split(":", 2);
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim().replaceAll("^\"|\"$", "");
                    String value = keyValue[1].trim();
                    
                    Object parsedValue = parseJsonValue(value);
                    result.put(key, parsedValue);
                }
            }
            
            return result;
        } catch (Exception e) {
            throw new JWTExtensionException(JWTExtensionException.ErrorType.TOKEN_PARSE_FAILED, 
                "Failed to parse JSON: " + e.getMessage());
        }
    }
    
    /**
     * Parse individual JSON values
     */
    private static Object parseJsonValue(String value) {
        value = value.trim();
        
        if (value.startsWith("\"") && value.endsWith("\"")) {
            // String value
            return value.substring(1, value.length() - 1);
        } else if ("true".equals(value)) {
            return Boolean.TRUE;
        } else if ("false".equals(value)) {
            return Boolean.FALSE;
        } else if ("null".equals(value)) {
            return null;
        } else {
            // Try to parse as number
            try {
                if (value.contains(".")) {
                    return Double.parseDouble(value);
                } else {
                    return Long.parseLong(value);
                }
            } catch (NumberFormatException e) {
                // Return as string if parsing fails
                return value;
            }
        }
    }
    
    /**
     * Clean token by removing prefixes and whitespace
     */
    private static String cleanToken(String token) {
        String clean = token.trim();
        
        if (clean.startsWith("Bearer ")) {
            clean = clean.substring(7).trim();
        } else if (clean.startsWith("JWT ")) {
            clean = clean.substring(4).trim();
        }
        
        return clean;
    }
    
    // Getter methods for immutable access
    public String getOriginalToken() { return originalToken; }
    public String getEncodedHeader() { return encodedHeader; }
    public String getEncodedPayload() { return encodedPayload; }
    public String getEncodedSignature() { return encodedSignature; }
    public Map<String, Object> getHeader() { return header; }
    public Map<String, Object> getPayload() { return payload; }
    public String getAlgorithm() { return algorithm; }
    public Optional<Long> getExpirationTime() { return Optional.ofNullable(expirationTime); }
    public Optional<Long> getIssuedAt() { return Optional.ofNullable(issuedAt); }
    public Optional<Long> getNotBefore() { return Optional.ofNullable(notBefore); }
    public boolean isValid() { return isValid; }
    public List<String> getValidationErrors() { return validationErrors; }
    public String getTokenId() { return tokenId; }
    
    // Utility methods
    public boolean isExpired() {
        return isExpired(System.currentTimeMillis() / 1000);
    }
    
    public boolean isExpired(long currentTimeSeconds) {
        return expirationTime != null && currentTimeSeconds > expirationTime;
    }
    
    public boolean isNotYetValid() {
        return isNotYetValid(System.currentTimeMillis() / 1000);
    }
    
    public boolean isNotYetValid(long currentTimeSeconds) {
        return notBefore != null && currentTimeSeconds < notBefore;
    }
    
    public boolean hasAlgorithm(String alg) {
        return alg != null && alg.equals(algorithm);
    }
    
    public boolean isSymmetricAlgorithm() {
        return algorithm != null && algorithm.startsWith("HS");
    }
    
    public boolean isAsymmetricAlgorithm() {
        return algorithm != null && (algorithm.startsWith("RS") || 
                                     algorithm.startsWith("ES") || 
                                     algorithm.startsWith("PS"));
    }
    
    public boolean isNoneAlgorithm() {
        return "none".equals(algorithm);
    }
    
    public Optional<String> getClaim(String claimName) {
        Object value = payload.get(claimName);
        return value != null ? Optional.of(value.toString()) : Optional.empty();
    }
    
    public Optional<String> getHeaderClaim(String claimName) {
        Object value = header.get(claimName);
        return value != null ? Optional.of(value.toString()) : Optional.empty();
    }
    
    /**
     * Format expiration time for display
     */
    public String getFormattedExpirationTime() {
        if (expirationTime == null) {
            return "No expiry";
        }
        
        try {
            LocalDateTime dateTime = LocalDateTime.ofInstant(
                Instant.ofEpochSecond(expirationTime), 
                ZoneId.systemDefault()
            );
            return dateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        } catch (Exception e) {
            logger.warn("Failed to format expiration time: %s", e.getMessage());
            return "Invalid time";
        }
    }
    
    /**
     * Create a new JWT with modified header
     */
    public ImmutableJWT withHeader(String key, Object value) throws JWTExtensionException {
        Map<String, Object> newHeader = new LinkedHashMap<>(this.header);
        newHeader.put(key, value);
        
        return Builder.fromJWT(this)
            .withHeader(newHeader)
            .build();
    }
    
    /**
     * Create a new JWT with modified payload
     */
    public ImmutableJWT withClaim(String key, Object value) throws JWTExtensionException {
        Map<String, Object> newPayload = new LinkedHashMap<>(this.payload);
        newPayload.put(key, value);
        
        return Builder.fromJWT(this)
            .withPayload(newPayload)
            .build();
    }
    
    /**
     * Create a new JWT with modified signature
     */
    public ImmutableJWT withSignature(String signature) throws JWTExtensionException {
        return Builder.fromJWT(this)
            .withEncodedSignature(signature)
            .build();
    }
    
    /**
     * Reconstruct the full JWT token
     */
    public String encode() {
        return encodedHeader + "." + encodedPayload + "." + encodedSignature;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        ImmutableJWT jwt = (ImmutableJWT) obj;
        return Objects.equals(originalToken, jwt.originalToken);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(originalToken);
    }
    
    @Override
    public String toString() {
        return String.format("JWT{alg=%s, exp=%s, valid=%s, errors=%d}", 
            algorithm, getFormattedExpirationTime(), isValid, validationErrors.size());
    }
    
    /**
     * Builder class for creating JWT instances
     */
    public static class Builder {
        private String originalToken;
        private String encodedHeader;
        private String encodedPayload;
        private String encodedSignature;
        private Map<String, Object> header = new LinkedHashMap<>();
        private Map<String, Object> payload = new LinkedHashMap<>();
        private String algorithm;
        private Long expirationTime;
        private Long issuedAt;
        private Long notBefore;
        private boolean isValid = true;
        private List<String> validationErrors = new ArrayList<>();
        
        public static Builder fromJWT(ImmutableJWT jwt) {
            Builder builder = new Builder();
            builder.originalToken = jwt.originalToken;
            builder.encodedHeader = jwt.encodedHeader;
            builder.encodedPayload = jwt.encodedPayload;
            builder.encodedSignature = jwt.encodedSignature;
            builder.header = new LinkedHashMap<>(jwt.header);
            builder.payload = new LinkedHashMap<>(jwt.payload);
            builder.algorithm = jwt.algorithm;
            builder.expirationTime = jwt.expirationTime;
            builder.issuedAt = jwt.issuedAt;
            builder.notBefore = jwt.notBefore;
            builder.isValid = jwt.isValid;
            builder.validationErrors = new ArrayList<>(jwt.validationErrors);
            return builder;
        }
        
        public Builder withOriginalToken(String token) {
            this.originalToken = token;
            return this;
        }
        
        public Builder withEncodedParts(String header, String payload, String signature) {
            this.encodedHeader = header;
            this.encodedPayload = payload;
            this.encodedSignature = signature;
            return this;
        }
        
        public Builder withEncodedSignature(String signature) {
            this.encodedSignature = signature;
            return this;
        }
        
        public Builder withHeader(Map<String, Object> header) {
            this.header = new LinkedHashMap<>(header);
            return this;
        }
        
        public Builder withPayload(Map<String, Object> payload) {
            this.payload = new LinkedHashMap<>(payload);
            return this;
        }
        
        public Builder extractCommonClaims() {
            // Extract algorithm from header
            Object alg = header.get("alg");
            if (alg != null) {
                this.algorithm = alg.toString();
            }
            
            // Extract time-based claims from payload
            Object exp = payload.get("exp");
            if (exp instanceof Number) {
                this.expirationTime = ((Number) exp).longValue();
            }
            
            Object iat = payload.get("iat");
            if (iat instanceof Number) {
                this.issuedAt = ((Number) iat).longValue();
            }
            
            Object nbf = payload.get("nbf");
            if (nbf instanceof Number) {
                this.notBefore = ((Number) nbf).longValue();
            }
            
            return this;
        }
        
        public Builder validate() {
            // Validate algorithm
            if (algorithm == null) {
                validationErrors.add("Missing algorithm in header");
                isValid = false;
            } else if (!SUPPORTED_ALGORITHMS.contains(algorithm)) {
                validationErrors.add("Unsupported algorithm: " + algorithm);
                isValid = false;
            }
            
            // Validate time claims
            long currentTime = System.currentTimeMillis() / 1000;
            
            if (expirationTime != null && currentTime > expirationTime) {
                validationErrors.add("Token has expired");
                isValid = false;
            }
            
            if (notBefore != null && currentTime < notBefore) {
                validationErrors.add("Token is not yet valid");
                isValid = false;
            }
            
            if (issuedAt != null && issuedAt > currentTime + 300) { // 5 minute tolerance
                validationErrors.add("Token issued in the future");
                isValid = false;
            }
            
            // Validate structure
            if (encodedHeader == null || encodedHeader.isEmpty()) {
                validationErrors.add("Missing or empty header");
                isValid = false;
            }
            
            if (encodedPayload == null || encodedPayload.isEmpty()) {
                validationErrors.add("Missing or empty payload");
                isValid = false;
            }
            
            return this;
        }
        
        public ImmutableJWT build() throws JWTExtensionException {
            return new ImmutableJWT(this);
        }
    }
    
    /**
     * Clear the parse cache
     */
    public static void clearCache() {
        PARSE_CACHE.clear();
        logger.info("ImmutableJWT parse cache cleared");
    }
    
    /**
     * Get cache statistics
     */
    public static String getCacheStats() {
        return String.format("ImmutableJWT Parse Cache: %d entries, max size: %d", 
            PARSE_CACHE.size(), MAX_CACHE_SIZE);
    }
}
