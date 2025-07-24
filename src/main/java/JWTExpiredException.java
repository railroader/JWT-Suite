/**
 * Specific exception for JWT expiration errors
 */
public class JWTExpiredException extends JWTException {
    private final long expiredAt;
    private final long currentTime;
    
    public JWTExpiredException(String message, long expiredAt, long currentTime) {
        super(ErrorCode.EXPIRED_TOKEN, message, formatExpirationContext(expiredAt, currentTime));
        this.expiredAt = expiredAt;
        this.currentTime = currentTime;
    }
    
    public long getExpiredAt() {
        return expiredAt;
    }
    
    public long getCurrentTime() {
        return currentTime;
    }
    
    public long getSecondsExpired() {
        return currentTime - expiredAt;
    }
    
    private static String formatExpirationContext(long expiredAt, long currentTime) {
        long secondsExpired = currentTime - expiredAt;
        return String.format("Expired %d seconds ago", secondsExpired);
    }
}
