import java.time.LocalDateTime;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpHeader;

/**
 * Data model for API call entries in the monitoring table
 */
public class APICallData {
    private final int requestNumber;
    private final String host;
    private final String type;
    private final String status;
    private final String risk;
    private final String found;
    private final String expires;
    private final LocalDateTime timestamp;
    
    // Store the actual request/response data
    private String requestData;
    private String responseData;
    private String url;
    private String method;
    private int statusCode;
    private String extractedJWT; // Store the JWT token from this specific request
    private HttpRequestToBeSent originalRequestToBeSent; // Store the original HttpRequestToBeSent object
    
    public APICallData(int requestNumber, String host, String type, String status, 
                      String risk, String found, String expires) {
        this.requestNumber = requestNumber;
        this.host = host;
        this.type = type;
        this.status = status;
        this.risk = risk;
        this.found = found;
        this.expires = expires;
        this.timestamp = LocalDateTime.now();
        this.requestData = "";
        this.responseData = "";
        this.url = "";
        this.method = "";
        this.statusCode = 0;
        this.extractedJWT = "";
        this.originalRequestToBeSent = null;
    }
    
    // Getters
    public int getRequestNumber() { return requestNumber; }
    public int getId() { return requestNumber; } // Alias for request number
    public String getHost() { return host; }
    public String getType() { return type; }
    public String getStatus() { return status; }
    public String getRisk() { return risk; }
    public String getFound() { return found; }
    public String getExpires() { return expires; }
    public LocalDateTime getTimestamp() { return timestamp; }
    
    public String getRequestData() { return requestData; }
    public String getResponseData() { return responseData; }
    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public int getStatusCode() { return statusCode; }
    public String getExtractedJWT() { return extractedJWT; }
    
    // Return HttpRequest for backward compatibility with Repeater/Intruder
    public HttpRequest getOriginalRequest() { 
        if (originalRequestToBeSent != null) {
            try {
                // Convert HttpRequestToBeSent to HttpRequest
                HttpRequest baseRequest = HttpRequest.httpRequest(originalRequestToBeSent.url())
                        .withMethod(originalRequestToBeSent.method())
                        .withBody(originalRequestToBeSent.bodyToString());
                
                // Add headers individually since withHeaders() doesn't exist
                for (HttpHeader header : originalRequestToBeSent.headers()) {
                    baseRequest = baseRequest.withHeader(header.name(), header.value());
                }
                
                return baseRequest;
            } catch (Exception e) {
                // If conversion fails, return a basic request
                return HttpRequest.httpRequest(originalRequestToBeSent.url())
                        .withMethod(originalRequestToBeSent.method());
            }
        }
        return null;
    }
    
    // New getter for the original type
    public HttpRequestToBeSent getOriginalRequestToBeSent() { return originalRequestToBeSent; }
    
    // Setters for request/response data
    public void setRequestData(String requestData) { this.requestData = requestData; }
    public void setResponseData(String responseData) { this.responseData = responseData; }
    public void setUrl(String url) { this.url = url; }
    public void setMethod(String method) { this.method = method; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
    public void setExtractedJWT(String extractedJWT) { this.extractedJWT = extractedJWT; }
    
    // Updated setter to store HttpRequestToBeSent
    public void setOriginalRequest(HttpRequestToBeSent originalRequestToBeSent) { 
        this.originalRequestToBeSent = originalRequestToBeSent; 
    }
    
    /**
     * Convert to table row data
     */
    public Object[] toTableRow() {
        return new Object[]{requestNumber, host, type, status, risk, found, expires, "View"};
    }
    
    /**
     * Get formatted request details
     */
    public String getFormattedRequestDetails() {
        StringBuilder sb = new StringBuilder();
        sb.append("Request #").append(requestNumber).append("\n");
        sb.append("Host: ").append(host).append("\n");
        sb.append("URL: ").append(url).append("\n");
        sb.append("Method: ").append(method).append("\n");
        sb.append("Type: ").append(type).append("\n");
        sb.append("Status: ").append(status).append("\n");
        sb.append("Risk: ").append(risk).append("\n");
        sb.append("Expires: ").append(expires).append("\n");
        sb.append("Timestamp: ").append(timestamp).append("\n");
        return sb.toString();
    }
}