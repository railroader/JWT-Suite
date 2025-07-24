import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Centralized logging system for JWT extension with structured output and context tracking
 * Provides different log levels and automatic context detection
 */
public class JWTExtensionLogger {
    
    public enum LogLevel {
        ERROR(4, "ERROR", "[!]"),
        WARN(3, "WARN", "[?]"),
        INFO(2, "INFO", "[i]"),
        DEBUG(1, "DEBUG", "[d]"),
        TRACE(0, "TRACE", "[t]");
        
        private final int priority;
        private final String name;
        private final String symbol;
        
        LogLevel(int priority, String name, String symbol) {
            this.priority = priority;
            this.name = name;
            this.symbol = symbol;
        }
        
        public int getPriority() { return priority; }
        public String getName() { return name; }
        public String getSymbol() { return symbol; }
    }
    
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final ConcurrentLinkedQueue<LogEntry> recentLogs = new ConcurrentLinkedQueue<>();
    private static final AtomicInteger logCounter = new AtomicInteger(0);
    private static final int MAX_RECENT_LOGS = 1000;
    
    private static volatile LogLevel currentLogLevel = LogLevel.INFO;
    private static volatile boolean enableConsoleOutput = true;
    
    private final String context;
    
    private static class LogEntry {
        final int id;
        final LocalDateTime timestamp;
        final LogLevel level;
        final String context;
        final String message;
        final String threadName;
        
        LogEntry(LogLevel level, String context, String message) {
            this.id = logCounter.incrementAndGet();
            this.timestamp = LocalDateTime.now();
            this.level = level;
            this.context = context;
            this.message = message;
            this.threadName = Thread.currentThread().getName();
        }
        
        String formatForDisplay() {
            return String.format("[%s] %s [%s] [%s] %s",
                timestamp.format(TIMESTAMP_FORMAT),
                level.getSymbol(),
                context,
                threadName,
                message
            );
        }
    }
    
    /**
     * Create logger for specific context (usually class name)
     */
    public static JWTExtensionLogger getLogger(String context) {
        return new JWTExtensionLogger(context);
    }
    
    /**
     * Create logger for specific class
     */
    public static JWTExtensionLogger getLogger(Class<?> clazz) {
        return new JWTExtensionLogger(clazz.getSimpleName());
    }
    
    private JWTExtensionLogger(String context) {
        this.context = context != null ? context : "Unknown";
    }
    
    /**
     * Log error message
     */
    public void error(String message) {
        log(LogLevel.ERROR, message);
    }
    
    public void error(String format, Object... args) {
        if (shouldLog(LogLevel.ERROR)) {
            log(LogLevel.ERROR, String.format(format, args));
        }
    }
    
    public void error(String message, Throwable throwable) {
        if (shouldLog(LogLevel.ERROR)) {
            String stackTrace = getStackTrace(throwable);
            log(LogLevel.ERROR, message + " | Exception: " + throwable.getMessage() + "\\n" + stackTrace);
        }
    }
    
    /**
     * Log warning message
     */
    public void warn(String message) {
        log(LogLevel.WARN, message);
    }
    
    public void warn(String format, Object... args) {
        if (shouldLog(LogLevel.WARN)) {
            log(LogLevel.WARN, String.format(format, args));
        }
    }
    
    /**
     * Log info message
     */
    public void info(String message) {
        log(LogLevel.INFO, message);
    }
    
    public void info(String format, Object... args) {
        if (shouldLog(LogLevel.INFO)) {
            log(LogLevel.INFO, String.format(format, args));
        }
    }
    
    /**
     * Log debug message
     */
    public void debug(String message) {
        log(LogLevel.DEBUG, message);
    }
    
    public void debug(String format, Object... args) {
        if (shouldLog(LogLevel.DEBUG)) {
            log(LogLevel.DEBUG, String.format(format, args));
        }
    }
    
    /**
     * Log trace message
     */
    public void trace(String message) {
        log(LogLevel.TRACE, message);
    }
    
    public void trace(String format, Object... args) {
        if (shouldLog(LogLevel.TRACE)) {
            log(LogLevel.TRACE, String.format(format, args));
        }
    }
    
    /**
     * Core logging method
     */
    private void log(LogLevel level, String message) {
        if (!shouldLog(level)) {
            return;
        }
        
        LogEntry entry = new LogEntry(level, context, message);
        
        // Add to recent logs queue
        recentLogs.offer(entry);
        
        // Maintain queue size
        while (recentLogs.size() > MAX_RECENT_LOGS) {
            recentLogs.poll();
        }
        
        // Output to console if enabled
        if (enableConsoleOutput) {
            System.out.println(entry.formatForDisplay());
        }
    }
    
    /**
     * Check if log level should be processed
     */
    private boolean shouldLog(LogLevel level) {
        return level.getPriority() >= currentLogLevel.getPriority();
    }
    
    /**
     * Get stack trace as string
     */
    private String getStackTrace(Throwable throwable) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        return sw.toString();
    }
    
    /**
     * Specialized logging methods for common JWT operations
     */
    public void logJWTOperation(String operation, String tokenPrefix) {
        if (shouldLog(LogLevel.DEBUG)) {
            String prefix = tokenPrefix != null && tokenPrefix.length() > 20 ? 
                tokenPrefix.substring(0, 20) + "..." : tokenPrefix;
            debug("JWT Operation: %s on token: %s", operation, prefix);
        }
    }
    
    public void logCryptoOperation(String operation, String algorithm) {
        debug("Crypto Operation: %s using algorithm: %s", operation, algorithm);
    }
    
    public void logPerformanceMetric(String operation, long durationMs) {
        if (durationMs > 1000) {
            warn("Slow operation detected: %s took %d ms", operation, durationMs);
        } else {
            debug("Performance: %s completed in %d ms", operation, durationMs);
        }
    }
    
    public void logSecurityEvent(String event, String details) {
        warn("Security Event: %s - %s", event, details);
    }
    
    public void logNetworkOperation(String operation, String endpoint, int statusCode) {
        info("Network: %s to %s returned %d", operation, endpoint, statusCode);
    }
    
    public void logMethodEntry(String methodName) {
        trace("Entering method: %s", methodName);
    }
    
    public void logMethodExit(String methodName) {
        trace("Exiting method: %s", methodName);
    }
    
    public void logMethodExit(String methodName, Object result) {
        trace("Exiting method: %s with result: %s", methodName, result);
    }
    
    /**
     * Configuration methods
     */
    public static void setLogLevel(LogLevel level) {
        currentLogLevel = level;
        System.out.println("[JWTLogger] Log level set to: " + level.getName());
    }
    
    public static void setConsoleOutput(boolean enabled) {
        enableConsoleOutput = enabled;
        if (enabled) {
            System.out.println("[JWTLogger] Console output enabled");
        }
    }
    
    public static LogLevel getCurrentLogLevel() {
        return currentLogLevel;
    }
    
    /**
     * Get recent log entries for debugging
     */
    public static String getRecentLogs(int count) {
        StringBuilder sb = new StringBuilder();
        LogEntry[] entries = recentLogs.toArray(new LogEntry[0]);
        
        int start = Math.max(0, entries.length - count);
        for (int i = start; i < entries.length; i++) {
            sb.append(entries[i].formatForDisplay()).append("\\n");
        }
        
        return sb.toString();
    }
    
    /**
     * Get logging statistics
     */
    public static String getLoggingStats() {
        return String.format("Logging Stats: Level=%s, Console=%s, Recent Logs=%d/%d", 
            currentLogLevel.getName(), enableConsoleOutput, recentLogs.size(), MAX_RECENT_LOGS);
    }
    
    /**
     * Clear recent logs
     */
    public static void clearRecentLogs() {
        recentLogs.clear();
        System.out.println("[JWTLogger] Recent logs cleared");
    }
}
