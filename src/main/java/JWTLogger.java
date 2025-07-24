import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Structured logging system for the JWT extension
 * Provides different logging levels, proper formatting, and context tracking
 */
public class JWTLogger {
    private static final String LOGGER_NAME = "JWT_EXTENSION";
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    
    private final Logger logger;
    private final String context;
    private static volatile boolean initialized = false;
    
    // Log levels
    public enum LogLevel {
        TRACE(Level.FINEST),
        DEBUG(Level.FINE),
        INFO(Level.INFO),
        WARN(Level.WARNING),
        ERROR(Level.SEVERE);
        
        private final Level javaLevel;
        
        LogLevel(Level javaLevel) {
            this.javaLevel = javaLevel;
        }
        
        public Level getJavaLevel() {
            return javaLevel;
        }
    }
    
    /**
     * Custom formatter for JWT extension logs
     */
    private static class JWTLogFormatter extends Formatter {
        @Override
        public String format(LogRecord record) {
            return String.format("[%s] [%s] [%s] %s%n",
                LocalDateTime.now().format(TIMESTAMP_FORMAT),
                record.getLevel().getName(),
                extractContext(record.getLoggerName()),
                record.getMessage()
            );
        }
        
        private String extractContext(String loggerName) {
            if (loggerName.contains(".")) {
                String[] parts = loggerName.split("\\.");
                return parts[parts.length - 1];
            }
            return loggerName;
        }
    }
    
    /**
     * Initialize the logging system (thread-safe, singleton pattern)
     */
    private static synchronized void initializeLogging() {
        if (initialized) {
            return;
        }
        
        try {
            Logger rootLogger = Logger.getLogger(LOGGER_NAME);
            rootLogger.setLevel(Level.ALL);
            rootLogger.setUseParentHandlers(false);
            
            // Console handler for immediate output to Burp
            ConsoleHandler consoleHandler = new ConsoleHandler();
            consoleHandler.setLevel(Level.INFO);
            consoleHandler.setFormatter(new JWTLogFormatter());
            rootLogger.addHandler(consoleHandler);
            
            // Optional file handler for detailed logging
            try {
                FileHandler fileHandler = new FileHandler("jwt-extension.log", true);
                fileHandler.setLevel(Level.ALL);
                fileHandler.setFormatter(new JWTLogFormatter());
                rootLogger.addHandler(fileHandler);
            } catch (IOException e) {
                // File logging failed, continue with console only
                System.err.println("JWT Extension: Could not initialize file logging: " + e.getMessage());
            }
            
            initialized = true;
            
        } catch (Exception e) {
            System.err.println("JWT Extension: Failed to initialize logging: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Create a logger for a specific context
     */
    public static JWTLogger getLogger(String context) {
        if (!initialized) {
            initializeLogging();
        }
        return new JWTLogger(context);
    }
    
    /**
     * Create a logger for a specific class
     */
    public static JWTLogger getLogger(Class<?> clazz) {
        return getLogger(clazz.getSimpleName());
    }
    
    private JWTLogger(String context) {
        this.context = context;
        this.logger = Logger.getLogger(LOGGER_NAME + "." + context);
    }
    
    // Logging methods with different levels
    public void trace(String message) {
        log(LogLevel.TRACE, message);
    }
    
    public void trace(String message, Object... args) {
        log(LogLevel.TRACE, message, args);
    }
    
    public void debug(String message) {
        log(LogLevel.DEBUG, message);
    }
    
    public void debug(String message, Object... args) {
        log(LogLevel.DEBUG, message, args);
    }
    
    public void info(String message) {
        log(LogLevel.INFO, message);
    }
    
    public void info(String message, Object... args) {
        log(LogLevel.INFO, message, args);
    }
    
    public void warn(String message) {
        log(LogLevel.WARN, message);
    }
    
    public void warn(String message, Object... args) {
        log(LogLevel.WARN, message, args);
    }
    
    public void warn(String message, Throwable throwable) {
        log(LogLevel.WARN, message, throwable);
    }
    
    public void error(String message) {
        log(LogLevel.ERROR, message);
    }
    
    public void error(String message, Object... args) {
        log(LogLevel.ERROR, message, args);
    }
    
    public void error(String message, Throwable throwable) {
        log(LogLevel.ERROR, message, throwable);
    }
    
    public void exception(String message, Exception e) {
        error(message + ": " + e.getMessage());
        if (logger.isLoggable(Level.FINE)) {
            error("Stack trace: ", e);
        }
    }
    
    // Core logging method
    private void log(LogLevel level, String message, Object... args) {
        if (logger.isLoggable(level.getJavaLevel())) {
            String formattedMessage;
            if (args.length > 0) {
                // Handle both string formatting and exception logging
                if (args.length == 1 && args[0] instanceof Throwable) {
                    logger.log(level.getJavaLevel(), message, (Throwable) args[0]);
                    return;
                } else {
                    formattedMessage = String.format(message, args);
                }
            } else {
                formattedMessage = message;
            }
            
            logger.log(level.getJavaLevel(), formattedMessage);
        }
    }
    
    private void log(LogLevel level, String message, Throwable throwable) {
        if (logger.isLoggable(level.getJavaLevel())) {
            logger.log(level.getJavaLevel(), message, throwable);
        }
    }
    
    // Utility methods for common logging patterns
    public void logMethodEntry(String methodName) {
        trace("Entering method: %s", methodName);
    }
    
    public void logMethodExit(String methodName) {
        trace("Exiting method: %s", methodName);
    }
    
    public void logMethodExit(String methodName, Object result) {
        trace("Exiting method: %s with result: %s", methodName, result);
    }
    
    public void logPerformance(String operation, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        debug("Performance: %s completed in %d ms", operation, duration);
    }
    
    public void logSecurity(String event, String details) {
        warn("Security Event: %s - %s", event, details);
    }
    
    public void logJWTOperation(String operation, String tokenPrefix) {
        debug("JWT Operation: %s on token: %s...", operation, 
              tokenPrefix != null && tokenPrefix.length() > 20 ? 
              tokenPrefix.substring(0, 20) : tokenPrefix);
    }
    
    public void logCryptoOperation(String operation, String algorithm) {
        debug("Crypto Operation: %s using algorithm: %s", operation, algorithm);
    }
    
    public void logNetworkOperation(String operation, String url, int statusCode) {
        info("Network Operation: %s to %s returned status: %d", operation, url, statusCode);
    }
    
    public void logUIOperation(String operation, String component) {
        trace("UI Operation: %s on component: %s", operation, component);
    }
    
    // Set log level for this logger
    public void setLevel(LogLevel level) {
        logger.setLevel(level.getJavaLevel());
    }
    
    // Check if a level is enabled
    public boolean isTraceEnabled() {
        return logger.isLoggable(LogLevel.TRACE.getJavaLevel());
    }
    
    public boolean isDebugEnabled() {
        return logger.isLoggable(LogLevel.DEBUG.getJavaLevel());
    }
    
    public boolean isInfoEnabled() {
        return logger.isLoggable(LogLevel.INFO.getJavaLevel());
    }
}
