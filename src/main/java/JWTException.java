/**
 * Custom exception hierarchy for JWT-related operations
 * Provides specific exception types for better error handling and recovery strategies
 */
public class JWTException extends Exception {
    private final ErrorCode errorCode;
    private final String context;
    
    public enum ErrorCode {
        INVALID_FORMAT("Invalid JWT format"),
        INVALID_SIGNATURE("Invalid JWT signature"),
        EXPIRED_TOKEN("JWT token has expired"),
        ALGORITHM_MISMATCH("JWT algorithm mismatch"),
        ENCODING_ERROR("Base64 encoding/decoding error"),
        CRYPTO_ERROR("Cryptographic operation failed"),
        PARSING_ERROR("JSON parsing error"),
        NETWORK_ERROR("Network communication error"),
        TIMEOUT_ERROR("Operation timed out"),
        CONFIGURATION_ERROR("Configuration error");
        
        private final String defaultMessage;
        
        ErrorCode(String defaultMessage) {
            this.defaultMessage = defaultMessage;
        }
        
        public String getDefaultMessage() {
            return defaultMessage;
        }
    }
    
    public JWTException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        this.context = null;
    }
    
    public JWTException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.context = null;
    }
    
    public JWTException(ErrorCode errorCode, String message, String context) {
        super(message);
        this.errorCode = errorCode;
        this.context = context;
    }
    
    public JWTException(ErrorCode errorCode, String message, String context, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.context = context;
    }
    
    public ErrorCode getErrorCode() {
        return errorCode;
    }
    
    public String getContext() {
        return context;
    }
    
    public boolean isRecoverable() {
        switch (errorCode) {
            case NETWORK_ERROR:
            case TIMEOUT_ERROR:
                return true;
            case EXPIRED_TOKEN:
                return true; // Can be recovered with token refresh
            default:
                return false;
        }
    }
    
    @Override
    public String getMessage() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(errorCode.name()).append("] ");
        
        String message = super.getMessage();
        if (message != null && !message.isEmpty()) {
            sb.append(message);
        } else {
            sb.append(errorCode.getDefaultMessage());
        }
        
        if (context != null && !context.isEmpty()) {
            sb.append(" (Context: ").append(context).append(")");
        }
        
        return sb.toString();
    }
    
    public String getDetailedMessage() {
        StringBuilder sb = new StringBuilder();
        sb.append(getMessage());
        
        if (getCause() != null) {
            sb.append("\nCause: ").append(getCause().getMessage());
        }
        
        return sb.toString();
    }
}
