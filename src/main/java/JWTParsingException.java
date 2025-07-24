/**
 * Specific exception for JWT parsing errors
 */
public class JWTParsingException extends JWTException {
    private final String invalidToken;
    
    public JWTParsingException(String message, String invalidToken) {
        super(ErrorCode.PARSING_ERROR, message, "Token: " + truncateToken(invalidToken));
        this.invalidToken = invalidToken;
    }
    
    public JWTParsingException(String message, String invalidToken, Throwable cause) {
        super(ErrorCode.PARSING_ERROR, message, "Token: " + truncateToken(invalidToken), cause);
        this.invalidToken = invalidToken;
    }
    
    public String getInvalidToken() {
        return invalidToken;
    }
    
    private static String truncateToken(String token) {
        if (token == null) return "null";
        return token.length() > 50 ? token.substring(0, 50) + "..." : token;
    }
}
