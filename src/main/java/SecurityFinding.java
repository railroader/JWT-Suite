/**
 * Represents a security finding from JWT analysis
 */
public class SecurityFinding {
    private String category;
    private String severity;
    private String message;
    private String vulnerableSnippet; // The actual part of the token that triggered this finding
    
    public SecurityFinding(String category, String severity, String message) {
        this.category = category;
        this.severity = severity;
        this.message = message;
        this.vulnerableSnippet = null;
    }
    
    public SecurityFinding(String category, String severity, String message, String vulnerableSnippet) {
        this.category = category;
        this.severity = severity;
        this.message = message;
        this.vulnerableSnippet = vulnerableSnippet;
    }
    
    public String getCategory() {
        return category;
    }
    
    public String getSeverity() {
        return severity;
    }
    
    public String getMessage() {
        return message;
    }
    
    public String getVulnerableSnippet() {
        return vulnerableSnippet;
    }
    
    public void setVulnerableSnippet(String vulnerableSnippet) {
        this.vulnerableSnippet = vulnerableSnippet;
    }
    
    public boolean hasVulnerableSnippet() {
        return vulnerableSnippet != null && !vulnerableSnippet.trim().isEmpty();
    }
    
    public int getSeverityOrder() {
        switch (severity.toLowerCase()) {
            case "critical": return 5;
            case "high": return 4;
            case "medium": return 3;
            case "low": return 2;
            case "info": return 1;
            default: return 0;
        }
    }
    
    public String getSeverityIcon() {
        switch (severity.toLowerCase()) {
            case "critical": return "🔴 CRITICAL";
            case "high": return "🟠 HIGH";
            case "medium": return "🟡 MEDIUM";
            case "low": return "🔵 LOW";
            case "info": return "ℹ️ INFO";
            default: return "⚪ " + severity.toUpperCase();
        }
    }
    
    /**
     * Get formatted message with vulnerable snippet if available
     */
    /**
     * Get title (alias for category)
     */
    public String getTitle() {
        return category;
    }
    
    /**
     * Get description (alias for message)
     */
    public String getDescription() {
        return message;
    }
    
    /**
     * Get details (alias for vulnerableSnippet for compatibility)
     */
    public String getDetails() {
        return vulnerableSnippet;
    }
    
    public String getFormattedMessage() {
        if (hasVulnerableSnippet()) {
            return message + "\n    ➡️ Found: " + formatSnippet(vulnerableSnippet);
        }
        return message;
    }
    
    private String formatSnippet(String snippet) {
        if (snippet == null || snippet.trim().isEmpty()) {
            return "";
        }
        
        // Limit snippet length to prevent overly long output
        String formatted = snippet.trim();
        if (formatted.length() > 100) {
            formatted = formatted.substring(0, 100) + "...";
        }
        
        // Add quotes if it's a string value
        if (!formatted.startsWith("\"") && !formatted.startsWith("{") && !formatted.startsWith("[")) {
            formatted = "\"" + formatted + "\"";
        }
        
        return formatted;
    }
}
