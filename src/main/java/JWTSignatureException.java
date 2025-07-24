/**
 * Specific exception for JWT signature validation errors
 */
public class JWTSignatureException extends JWTException {
    private final String algorithm;
    private final String expectedSignature;
    private final String actualSignature;
    
    public JWTSignatureException(String message, String algorithm) {
        super(ErrorCode.INVALID_SIGNATURE, message, "Algorithm: " + algorithm);
        this.algorithm = algorithm;
        this.expectedSignature = null;
        this.actualSignature = null;
    }
    
    public JWTSignatureException(String message, String algorithm, String expectedSignature, String actualSignature) {
        super(ErrorCode.INVALID_SIGNATURE, message, "Algorithm: " + algorithm);
        this.algorithm = algorithm;
        this.expectedSignature = expectedSignature;
        this.actualSignature = actualSignature;
    }
    
    public String getAlgorithm() {
        return algorithm;
    }
    
    public String getExpectedSignature() {
        return expectedSignature;
    }
    
    public String getActualSignature() {
        return actualSignature;
    }
}
