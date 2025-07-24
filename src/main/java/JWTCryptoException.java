/**
 * Specific exception for crypto operation failures
 */
public class JWTCryptoException extends JWTExtensionException {
    private final String algorithm;
    private final String operation;
    
    public JWTCryptoException(String message, String algorithm, String operation) {
        super(ErrorType.CRYPTO_OPERATION_FAILED, message, "Algorithm: " + algorithm + ", Operation: " + operation);
        this.algorithm = algorithm;
        this.operation = operation;
    }
    
    public JWTCryptoException(String message, String algorithm, String operation, Throwable cause) {
        super(ErrorType.CRYPTO_OPERATION_FAILED, message, "Algorithm: " + algorithm + ", Operation: " + operation, cause);
        this.algorithm = algorithm;
        this.operation = operation;
    }
    
    public String getAlgorithm() {
        return algorithm;
    }
    
    public String getOperation() {
        return operation;
    }
}
