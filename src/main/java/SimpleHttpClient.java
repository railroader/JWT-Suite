import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple HTTP client for making requests through Burp's API
 * with fallback to Java's HttpURLConnection
 */
public class SimpleHttpClient {
    private final MontoyaApi api;
    private boolean useJavaFallback = true; // Default to true for backward compatibility
    
    public SimpleHttpClient(MontoyaApi api) {
        this.api = api;
    }
    
    /**
     * Set whether to use Java HTTP fallback when Burp API fails
     * @param enable true to enable fallback (default), false to disable for BApp Store compliance
     */
    public void setUseJavaFallback(boolean enable) {
        this.useJavaFallback = enable;
        api.logging().logToOutput("[HTTP-CONFIG] Java HTTP fallback " + (enable ? "ENABLED" : "DISABLED"));
    }
    
    /**
     * Check if Java HTTP fallback is enabled
     * @return true if fallback is enabled
     */
    public boolean isJavaFallbackEnabled() {
        return this.useJavaFallback;
    }
    
    /**
     * Send a POST request with JSON body using Java's HttpURLConnection
     * This is a fallback method when Burp's API hangs
     */
    public String sendPostWithJavaHttp(String url, String jsonBody) {
        if (!useJavaFallback) {
            api.logging().logToError("[HTTP-JAVA] Java HTTP fallback is DISABLED - cannot proceed with fallback request");
            return null;
        }
        
        HttpURLConnection connection = null;
        try {
            api.logging().logToOutput("[HTTP-JAVA] Using Java HttpURLConnection fallback");
            
            URL urlObj = new URL(url);
            connection = (HttpURLConnection) urlObj.openConnection();
            
            // Configure connection with robust timeout settings
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("User-Agent", "JWT Manager Burp Extension");
            connection.setConnectTimeout(8000); // 8 seconds - longer for auth servers
            connection.setReadTimeout(8000); // 8 seconds
            
            // Send request body with error handling
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonBody.getBytes("utf-8");
                os.write(input, 0, input.length);
                os.flush(); // Ensure data is sent
            } catch (Exception outputException) {
                api.logging().logToError("[HTTP-JAVA] Error writing request body: " + outputException.getMessage());
                throw outputException;
            }
            
            // Get response with comprehensive error handling
            int responseCode = connection.getResponseCode();
            String responseMessage = connection.getResponseMessage();
            api.logging().logToOutput("[HTTP-JAVA] Response: " + responseCode + " " + responseMessage);
            
            // Handle different response codes appropriately
            if (responseCode >= 400) {
                api.logging().logToError("[HTTP-JAVA] Authentication error - Status: " + responseCode + " " + responseMessage);
                
                // For auth errors, still try to read the error response
                if (responseCode == 401) {
                    api.logging().logToError("[HTTP-JAVA] Authentication failed - Invalid credentials");
                } else if (responseCode == 403) {
                    api.logging().logToError("[HTTP-JAVA] Authentication forbidden - Access denied");
                } else if (responseCode >= 500) {
                    api.logging().logToError("[HTTP-JAVA] Server error - Authentication server may be down");
                }
            }
            
            // Read response body (works for both success and error responses)
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(
                        responseCode >= 200 && responseCode < 400 
                            ? connection.getInputStream() 
                            : connection.getErrorStream(), 
                        "utf-8"))) {
                
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            } catch (Exception readException) {
                api.logging().logToError("[HTTP-JAVA] Error reading response: " + readException.getMessage());
                // Don't throw here - we want to return what we can
            }
            
            String responseBody = response.toString();
            api.logging().logToOutput("[HTTP-JAVA] Response body length: " + responseBody.length());
            
            // Log response body for debugging auth failures
            if (responseCode >= 400) {
                api.logging().logToError("[HTTP-JAVA] Error response body: " + responseBody);
            } else {
                api.logging().logToOutput("[HTTP-JAVA] Success response body: " + 
                    (responseBody.length() > 200 ? responseBody.substring(0, 200) + "..." : responseBody));
            }
            
            // Return response body even for error codes - the caller will handle it
            return responseBody;
            
        } catch (java.net.SocketTimeoutException e) {
            api.logging().logToError("[HTTP-JAVA] Timeout connecting to authentication server: " + e.getMessage());
            return null;
        } catch (java.net.ConnectException e) {
            api.logging().logToError("[HTTP-JAVA] Cannot connect to authentication server: " + e.getMessage());
            return null;
        } catch (java.net.UnknownHostException e) {
            api.logging().logToError("[HTTP-JAVA] Unknown host - check authentication server URL: " + e.getMessage());
            return null;
        } catch (Exception e) {
            api.logging().logToError("[HTTP-JAVA] Unexpected exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        } finally {
            if (connection != null) {
                try {
                    connection.disconnect();
                } catch (Exception disconnectException) {
                    // Ignore disconnect errors
                }
            }
        }
    }
    
    /**
     * Send a POST request with JSON body
     * @param url The target URL
     * @param jsonBody The JSON request body
     * @param headers Additional headers (optional)
     * @return HttpResponse or null if failed
     */
    public HttpResponse sendPostRequest(String url, String jsonBody, Map<String, String> headers) {
        try {
            api.logging().logToOutput("[HTTP] Preparing POST request to: " + url);
            
            // Parse URL
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost();
            int port = parsedUrl.getPort();
            if (port == -1) {
                port = parsedUrl.getDefaultPort();
            }
            boolean useHttps = parsedUrl.getProtocol().equalsIgnoreCase("https");
            String path = parsedUrl.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            
            api.logging().logToOutput("[HTTP] Host: " + host + ", Port: " + port + ", Path: " + path);
            
            // Create HttpService
            HttpService httpService = HttpService.httpService(host, port, useHttps);
            
            // Build raw HTTP request to avoid withHeader issues
            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append("POST ").append(path).append(" HTTP/1.1\r\n");
            rawRequest.append("Host: ").append(host);
            if (port != 80 && port != 443) {
                rawRequest.append(":").append(port);
            }
            rawRequest.append("\r\n");
            
            // Add default headers
            rawRequest.append("Content-Type: application/json\r\n");
            rawRequest.append("Accept: application/json\r\n");
            rawRequest.append("User-Agent: JWT Manager Burp Extension\r\n");
            rawRequest.append("Content-Length: ").append(jsonBody.length()).append("\r\n");
            rawRequest.append("Connection: close\r\n");
            
            // Add custom headers if provided
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    rawRequest.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
                }
            }
            
            // Add body
            rawRequest.append("\r\n");
            rawRequest.append(jsonBody);
            
            String rawRequestString = rawRequest.toString();
            
            // Log the full request
            api.logging().logToOutput("[HTTP] ===== FULL REQUEST =====");
            api.logging().logToOutput(rawRequestString.replace("\r\n", "\\r\\n"));
            api.logging().logToOutput("[HTTP] ===== END REQUEST =====");
            
            // Create HttpRequest
            HttpRequest request = HttpRequest.httpRequest(httpService, rawRequestString);
            
            // Try to send the request with a timeout mechanism
            api.logging().logToOutput("[HTTP] Attempting to send request via Burp API...");
            
            // Log the HttpService details
            api.logging().logToOutput("[HTTP] HttpService details - Host: " + httpService.host() + 
                                     ", Port: " + httpService.port() + 
                                     ", Secure: " + httpService.secure());
            
            // Create a thread to send the request with enhanced timeout and error handling
            final HttpRequestResponse[] resultHolder = new HttpRequestResponse[1];
            final Exception[] exceptionHolder = new Exception[1];
            final boolean[] completedFlag = new boolean[1];
            
            Thread requestThread = new Thread(() -> {
                try {
                    api.logging().logToOutput("[HTTP-THREAD] About to call sendRequest...");
                    resultHolder[0] = api.http().sendRequest(request);
                    completedFlag[0] = true;
                    api.logging().logToOutput("[HTTP-THREAD] sendRequest completed successfully");
                } catch (Exception e) {
                    api.logging().logToError("[HTTP-THREAD] Exception in request: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    exceptionHolder[0] = e;
                    completedFlag[0] = true;
                    // Don't print full stack trace for expected errors
                    if (!(e instanceof java.net.SocketTimeoutException || e instanceof java.net.ConnectException)) {
                        e.printStackTrace();
                    }
                }
            });
            
            requestThread.setName("JWT-Auth-Request-Thread");
            requestThread.setDaemon(true); // Ensure it doesn't prevent JVM shutdown
            requestThread.start();
            
            try {
                requestThread.join(8000); // Wait max 8 seconds for auth requests
            } catch (InterruptedException e) {
                api.logging().logToError("[HTTP] Request thread interrupted");
                Thread.currentThread().interrupt(); // Restore interrupt flag
            }
            
            if (requestThread.isAlive()) {
                api.logging().logToError("[HTTP] Request timed out after 8 seconds - triggering fallback");
                requestThread.interrupt();
                
                // Give the thread a moment to clean up
                try {
                    requestThread.join(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                
                // Return null to trigger fallback in SessionManagement
                return null;
            }
            
            if (exceptionHolder[0] != null) {
                Exception ex = exceptionHolder[0];
                api.logging().logToError("[HTTP] Request failed with exception: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
                
                // Don't return null for certain exceptions - try to get more info
                if (ex instanceof java.net.SocketTimeoutException) {
                    api.logging().logToError("[HTTP] Timeout - will attempt Java HTTP fallback");
                } else if (ex instanceof java.net.ConnectException) {
                    api.logging().logToError("[HTTP] Connection refused - will attempt Java HTTP fallback");
                }
                
                return null;
            }
            
            HttpRequestResponse result = resultHolder[0];
            
            if (result == null) {
                api.logging().logToError("[HTTP] No response received - result is null");
                return null;
            }
            
            HttpResponse response = result.response();
            if (response == null) {
                api.logging().logToError("[HTTP] No response object in result");
                return null;
            }
            
            // Log response details with error handling awareness
            api.logging().logToOutput("[HTTP] ===== RESPONSE RECEIVED =====");
            int statusCode = response.statusCode();
            String reasonPhrase = response.reasonPhrase();
            api.logging().logToOutput("[HTTP] Status: " + statusCode + " " + reasonPhrase);
            
            // Log status code analysis for debugging
            if (statusCode >= 400) {
                if (statusCode == 401) {
                    api.logging().logToError("[HTTP] Authentication failed - Invalid credentials (401)");
                } else if (statusCode == 403) {
                    api.logging().logToError("[HTTP] Access forbidden (403)");
                } else if (statusCode >= 500) {
                    api.logging().logToError("[HTTP] Server error (" + statusCode + ") - Authentication server issue");
                } else {
                    api.logging().logToError("[HTTP] Client error (" + statusCode + ") - Check request format");
                }
            }
            
            api.logging().logToOutput("[HTTP] Headers:");
            try {
                for (int i = 0; i < response.headers().size(); i++) {
                    api.logging().logToOutput("[HTTP]   " + response.headers().get(i).name() + ": " + response.headers().get(i).value());
                }
            } catch (Exception headerException) {
                api.logging().logToError("[HTTP] Error reading headers: " + headerException.getMessage());
            }
            
            String responseBody = null;
            try {
                responseBody = response.bodyToString();
            } catch (Exception bodyException) {
                api.logging().logToError("[HTTP] Error reading response body: " + bodyException.getMessage());
            }
            
            api.logging().logToOutput("[HTTP] Body length: " + (responseBody != null ? responseBody.length() : 0));
            
            // Log response body appropriately
            if (statusCode >= 400) {
                api.logging().logToError("[HTTP] Error response body: " + (responseBody != null ? responseBody : "null"));
            } else {
                api.logging().logToOutput("[HTTP] Body: " + (responseBody != null ? responseBody : "null"));
            }
            
            api.logging().logToOutput("[HTTP] ===== END RESPONSE =====");
            
            return response;
            
        } catch (java.net.MalformedURLException e) {
            api.logging().logToError("[HTTP] Invalid URL format: " + e.getMessage());
            return null;
        } catch (Exception e) {
            api.logging().logToError("[HTTP] Unexpected exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            // Only print stack trace for unexpected exceptions
            if (!(e instanceof java.net.SocketTimeoutException || 
                  e instanceof java.net.ConnectException ||
                  e instanceof java.net.UnknownHostException)) {
                e.printStackTrace();
            }
            return null;
        }
    }
    
    /**
     * Send a GET request
     * @param url The target URL
     * @param headers Additional headers (optional)
     * @return HttpResponse or null if failed
     */
    public HttpResponse sendGetRequest(String url, Map<String, String> headers) {
        try {
            api.logging().logToOutput("[HTTP] Preparing GET request to: " + url);
            
            // Parse URL
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost();
            int port = parsedUrl.getPort();
            if (port == -1) {
                port = parsedUrl.getDefaultPort();
            }
            boolean useHttps = parsedUrl.getProtocol().equalsIgnoreCase("https");
            String path = parsedUrl.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            String query = parsedUrl.getQuery();
            if (query != null && !query.isEmpty()) {
                path = path + "?" + query;
            }
            
            // Create HttpService
            HttpService httpService = HttpService.httpService(host, port, useHttps);
            
            // Build raw HTTP request
            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append("GET ").append(path).append(" HTTP/1.1\r\n");
            rawRequest.append("Host: ").append(host);
            if (port != 80 && port != 443) {
                rawRequest.append(":").append(port);
            }
            rawRequest.append("\r\n");
            rawRequest.append("Accept: application/json\r\n");
            rawRequest.append("User-Agent: JWT Manager Burp Extension\r\n");
            rawRequest.append("Connection: close\r\n");
            
            // Add custom headers if provided
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    rawRequest.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
                }
            }
            
            rawRequest.append("\r\n");
            
            String rawRequestString = rawRequest.toString();
            
            // Create and send request
            HttpRequest request = HttpRequest.httpRequest(httpService, rawRequestString);
            HttpRequestResponse result = api.http().sendRequest(request);
            
            if (result != null && result.response() != null) {
                return result.response();
            }
            
            return null;
            
        } catch (Exception e) {
            api.logging().logToError("[HTTP] GET request exception: " + e.getMessage());
            return null;
        }
    }
}
