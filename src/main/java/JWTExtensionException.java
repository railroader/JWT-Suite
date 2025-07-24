/**
 * Custom JWT extension exception hierarchy for improved error handling
 * Provides specific error types for different failure scenarios
 */
public class JWTExtensionException extends Exception {
    
    public enum ErrorType {
        TOKEN_PARSE_FAILED("Failed to parse JWT token structure"),
        INVALID_SIGNATURE("JWT signature validation failed"),
        TOKEN_EXPIRED("JWT token has expired"),
        ALGORITHM_NOT_SUPPORTED("JWT algorithm not supported"),
        CRYPTO_OPERATION_FAILED("Cryptographic operation failed"),
        NETWORK_REQUEST_FAILED("Network request failed"),
        INVALID_CONFIGURATION("Extension configuration is invalid"),
        RESOURCE_CLEANUP_FAILED("Failed to cleanup resources"),
        UI_OPERATION_FAILED("User interface operation failed");
        
        private final String defaultMessage;
        
        ErrorType(String defaultMessage) {
            this.defaultMessage = defaultMessage;
        }
        
        public String getDefaultMessage() {
            return defaultMessage;
        }
    }
    
    private final ErrorType errorType;
    private final String operationContext;
    private final long timestampMs;
    
    public JWTExtensionException(ErrorType errorType, String message) {
        super(message);
        this.errorType = errorType;
        this.operationContext = null;
        this.timestampMs = System.currentTimeMillis();
    }
    
    public JWTExtensionException(ErrorType errorType, String message, Throwable cause) {
        super(message, cause);
        this.errorType = errorType;
        this.operationContext = null;
        this.timestampMs = System.currentTimeMillis();
    }
    
    public JWTExtensionException(ErrorType errorType, String message, String operationContext) {
        super(message);
        this.errorType = errorType;
        this.operationContext = operationContext;
        this.timestampMs = System.currentTimeMillis();
    }
    
    public JWTExtensionException(ErrorType errorType, String message, String operationContext, Throwable cause) {
        super(message, cause);
        this.errorType = errorType;
        this.operationContext = operationContext;
        this.timestampMs = System.currentTimeMillis();
    }
    
    public ErrorType getErrorType() {
        return errorType;
    }
    
    public String getOperationContext() {
        return operationContext;
    }
    
    public long getTimestamp() {
        return timestampMs;
    }
    
    /**
     * Check if this error is recoverable
     */
    public boolean isRecoverable() {
        switch (errorType) {
            case NETWORK_REQUEST_FAILED:
            case RESOURCE_CLEANUP_FAILED:
                return true;
            case TOKEN_EXPIRED:
                return true; // Can potentially refresh
            default:
                return false;
        }
    }
    
    /**
     * Get detailed error message with context
     */
    public String getDetailedMessage() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(errorType.name()).append("] ");
        sb.append(getMessage() != null ? getMessage() : errorType.getDefaultMessage());
        
        if (operationContext != null) {
            sb.append(" (Context: ").append(operationContext).append(")");
        }
        
        if (getCause() != null) {
            sb.append(" | Caused by: ").append(getCause().getMessage());
        }
        
        return sb.toString();
    }
    
    @Override
    public String toString() {
        return getDetailedMessage();
    }
}
