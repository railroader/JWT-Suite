import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Annotations;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * HTTP handler to remove highlighting from requests/responses containing JWT tokens
 */
public class JWTHighlightRemover implements HttpHandler {
    private final MontoyaApi api;
    private final Pattern jwtPattern;
    private boolean enabled;
    
    public JWTHighlightRemover(MontoyaApi api) {
        this.api = api;
        this.enabled = true;
        
        // JWT pattern: three base64url-encoded parts separated by dots
        this.jwtPattern = Pattern.compile("(eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*)");
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!enabled) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        try {
            // Check if request contains JWT
            String requestString = requestToBeSent.toString();
            if (containsJWT(requestString)) {
                // Remove any existing highlighting by setting to none
                Annotations newAnnotations = requestToBeSent.annotations().withHighlightColor(HighlightColor.NONE);
                
                api.logging().logToOutput("JWT Highlight Remover: Removed highlighting from request with JWT");
                
                return RequestToBeSentAction.continueWith(requestToBeSent, newAnnotations);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error in JWT highlight remover (request): " + e.getMessage());
        }
        
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }
    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!enabled) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        try {
            // Check if request or response contains JWT
            String requestString = responseReceived.initiatingRequest().toString();
            String responseString = responseReceived.toString();
            
            boolean requestHasJWT = containsJWT(requestString);
            boolean responseHasJWT = containsJWT(responseString);
            
            if (requestHasJWT || responseHasJWT) {
                // Remove any existing highlighting by setting to none
                Annotations newAnnotations = responseReceived.annotations().withHighlightColor(HighlightColor.NONE);
                
                api.logging().logToOutput("JWT Highlight Remover: Removed highlighting from response with JWT");
                
                return ResponseReceivedAction.continueWith(responseReceived, newAnnotations);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error in JWT highlight remover (response): " + e.getMessage());
        }
        
        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    /**
     * Check if the HTTP message contains JWT tokens
     */
    private boolean containsJWT(String httpMessage) {
        try {
            Matcher matcher = jwtPattern.matcher(httpMessage);
            return matcher.find();
        } catch (Exception e) {
            api.logging().logToError("Error checking for JWT in message: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Enable or disable the JWT highlight remover
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        api.logging().logToOutput("JWT Highlight Remover: " + (enabled ? "Enabled" : "Disabled"));
    }
    
    /**
     * Check if the highlight remover is enabled
     */
    public boolean isEnabled() {
        return enabled;
    }
}
