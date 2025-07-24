import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Utility class for formatting HTTP requests and responses for display
 */
public class HttpFormatter {
    
    /**
     * Format HTTP request for display
     * @param request HTTP request to format
     * @return Formatted request string
     */
    public static String formatRequest(HttpRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append(request.method()).append(" ").append(request.path()).append(" HTTP/1.1\n");
        
        // Add headers (Host header is already included in the headers list)
        for (HttpHeader header : request.headers()) {
            sb.append(header.name()).append(": ").append(header.value()).append("\n");
        }
        
        sb.append("\n");
        
        // Add body if present
        if (request.body().length() > 0) {
            sb.append(request.bodyToString());
        }
        
        return sb.toString();
    }
    
    /**
     * Format HTTP response for display
     * @param response HTTP response to format
     * @return Formatted response string
     */
    public static String formatResponse(HttpResponse response) {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(response.statusCode()).append(" ").append(response.reasonPhrase()).append("\n");
        
        // Add headers
        for (HttpHeader header : response.headers()) {
            sb.append(header.name()).append(": ").append(header.value()).append("\n");
        }
        
        sb.append("\n");
        
        // Add body if present
        if (response.body().length() > 0) {
            sb.append(response.bodyToString());
        }
        
        return sb.toString();
    }
    
    /**
     * Create sample HTTP request for testing
     * @param host Host name
     * @param path Request path
     * @param method HTTP method
     * @param jwt JWT token to include
     * @return Formatted sample request
     */
    public static String createSampleRequest(String host, String path, String method, String jwt) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ").append(path).append(" HTTP/1.1\n");
        sb.append("Host: ").append(host).append("\n");
        sb.append("Authorization: Bearer ").append(jwt).append("\n");
        sb.append("Content-Type: application/json\n");
        sb.append("User-Agent: Burp JWT Manager\n");
        sb.append("\n");
        return sb.toString();
    }
    
    /**
     * Create sample HTTP response for testing
     * @param statusCode HTTP status code
     * @param message Response message
     * @return Formatted sample response
     */
    public static String createSampleResponse(int statusCode, String message) {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(statusCode);
        
        if (statusCode == 200) {
            sb.append(" OK\n");
        } else if (statusCode == 401) {
            sb.append(" Unauthorized\n");
        } else {
            sb.append(" Status\n");
        }
        
        sb.append("Content-Type: application/json\n");
        sb.append("Content-Length: ").append(message.length()).append("\n");
        sb.append("\n");
        sb.append(message);
        
        return sb.toString();
    }
    
    /**
     * Parse HTTP request from string format
     * @param requestData String representation of HTTP request
     * @return HttpRequest object or null if parsing fails
     */
    public static HttpRequest parseHttpRequest(String requestData) {
        try {
            if (requestData == null || requestData.trim().isEmpty()) {
                return null;
            }
            
            // Use Burp's built-in HTTP request parsing
            return HttpRequest.httpRequest(requestData);
        } catch (Exception e) {
            // If parsing fails, return null
            return null;
        }
    }
    
    /**
     * Parse HTTP response from string format
     * @param responseData String representation of HTTP response
     * @return HttpResponse object or null if parsing fails
     */
    public static HttpResponse parseHttpResponse(String responseData) {
        try {
            if (responseData == null || responseData.trim().isEmpty()) {
                return null;
            }
            
            // Use Burp's built-in HTTP response parsing
            return HttpResponse.httpResponse(responseData);
        } catch (Exception e) {
            // If parsing fails, return null
            return null;
        }
    }
}