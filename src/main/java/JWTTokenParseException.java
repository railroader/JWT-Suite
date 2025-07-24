/**
 * Specific exception for JWT token parsing failures
 */
public class JWTTokenParseException extends JWTExtensionException {
    private final String problematicToken;
    
    public JWTTokenParseException(String message, String token) {
        super(ErrorType.TOKEN_PARSE_FAILED, message, "Token: " + truncateForDisplay(token));
        this.problematicToken = token;
    }
    
    public JWTTokenParseException(String message, String token, Throwable cause) {
        super(ErrorType.TOKEN_PARSE_FAILED, message, "Token: " + truncateForDisplay(token), cause);
        this.problematicToken = token;
    }
    
    public String getProblematicToken() {
        return problematicToken;
    }
    
    private static String truncateForDisplay(String token) {
        if (token == null) return "null";
        return token.length() > 50 ? token.substring(0, 50) + "..." : token;
    }
}
