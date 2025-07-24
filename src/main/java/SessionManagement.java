import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.*;
import burp.api.montoya.http.message.requests.*;
import burp.api.montoya.http.message.responses.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Comparator;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class SessionManagement implements HttpHandler {
    // JWT Vault - the central storage for the current valid JWT
    private String jwtVault;

    // Configuration fields
    private String authUrl;
    private String username;
    private String password;
    private String jwtHeaderName;
    private String jwtPrefix;
    private String tokenPropertyName;
    private boolean enabled;
    private boolean useJavaHttpFallback = false; // Default to false for BApp Store compliance
    private MontoyaApi api;

    // SAVED configuration fields (only updated when Save Config is pressed)
    private String savedHttpMethod;
    private String savedContentType;
    private String savedRequestBody;

    // UI Components
    private JTextField authUrlField;
    private JTextField usernameField;
    private JTextField passwordField;
    private JTextField jwtHeaderField;
    private JTextField jwtPrefixField;
    private JTextField tokenPropertyField;
    private JCheckBox enabledCheckbox;

    private JTextArea requestBodyArea;
    private JComboBox<String> httpMethodCombo;
    private JTextField contentTypeField;
    private JTextArea currentJwtArea;

    // API Calls Table
    private APICallTableModel apiCallTableModel;
    private JTable apiCallsTable;
    private SimpleDateFormat dateFormat;
    private TableRowSorter<APICallTableModel> tableSorter;
    private int requestCounter = 0;

    // Date formatters
    private DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");
    private DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public SessionManagement(MontoyaApi api) {
        this.api = api;
        this.enabled = false;
        this.authUrl = "http://localhost:3000/auth";
        this.username = "admin";
        this.password = "password123";
        this.jwtHeaderName = "Authorization";
        this.jwtPrefix = "Bearer ";
        this.tokenPropertyName = "token";
        this.jwtVault = ""; // Initialize empty vault
        this.dateFormat = new SimpleDateFormat("HH:mm:ss");

        // Initialize saved configuration with defaults
        this.savedHttpMethod = "POST";
        this.savedContentType = "application/json";
        this.savedRequestBody = "{\"username\":\"[USERNAME]\",\"password\":\"[PASSWORD]\"}";

        // Initialize custom table model
        this.apiCallTableModel = new APICallTableModel();
    }

    // Method to store JWT in vault
    private void storeJWTInVault(String jwt) {
        if (jwt == null) {
            jwt = "";
        }

        final String finalJwt = jwt;
        final String finalExpirationTime = getJWTExpirationTime(jwt);

        this.jwtVault = finalJwt;
        api.logging().logToOutput("[VAULT] JWT stored in vault: " + (!finalJwt.isEmpty() ? finalJwt.substring(0, Math.min(30, finalJwt.length())) + "..." : "EMPTY"));
        api.logging().logToOutput("[VAULT] JWT expires: " + finalExpirationTime);

        // Update the JWT display area
        if (currentJwtArea != null) {
            SwingUtilities.invokeLater(() -> {
                if (finalJwt.isEmpty()) {
                    currentJwtArea.setText("Vault: EMPTY\n\nNo JWT available for injection");
                } else {
                    currentJwtArea.setText("Vault: " + finalJwt + "\n\nExpires: " + finalExpirationTime);
                }
            });
        }
    }

    // Method to clear vault (called on 401 responses)
    private void clearJWTVault() {
        api.logging().logToOutput("[VAULT] Clearing JWT vault due to 401 response");
        storeJWTInVault("");
    }

    // Method to check if vault is empty
    private boolean isVaultEmpty() {
        return jwtVault == null || jwtVault.trim().isEmpty();
    }

    // Method to get JWT from vault
    private String getJWTFromVault() {
        return jwtVault != null ? jwtVault : "";
    }

    // Method to parse JWT and extract expiration time
    private String getJWTExpirationTime(String jwt) {
        return JWTUtils.getExpirationTime(jwt);
    }

    // Method to get JWT expiration status for risk assessment
    private String getJWTExpirationRisk(String expirationTime) {
        return JWTUtils.getExpirationRisk(expirationTime);
    }

    // Legacy method for backward compatibility - now stores in vault
    public void storeJWT(String jwt) {
        storeJWTInVault(jwt);
    }

    // Method to extract JWT from JSON string response (for Java HTTP fallback)
    private String extractJWTFromJson(String jsonResponse) {
        api.logging().logToOutput("[EXTRACT-JSON] Extracting JWT from JSON response");

        try {
            if (jsonResponse == null || jsonResponse.trim().isEmpty()) {
                api.logging().logToError("[EXTRACT-JSON] Response is empty");
                return null;
            }

            // Use the configured token property name
            String primaryPattern = "\"" + tokenPropertyName + "\":";

            // Patterns to try
            String[] patterns = {
                    primaryPattern,
                    "\"token\":", "\"access_token\":", "\"jwt\":", "\"accessToken\":"
            };

            for (String pattern : patterns) {
                int tokenStart = jsonResponse.indexOf(pattern);
                if (tokenStart != -1) {
                    int valueStart = tokenStart + pattern.length();

                    // Skip whitespace
                    while (valueStart < jsonResponse.length() &&
                            Character.isWhitespace(jsonResponse.charAt(valueStart))) {
                        valueStart++;
                    }

                    // Skip opening quote
                    if (valueStart < jsonResponse.length() &&
                            jsonResponse.charAt(valueStart) == '"') {
                        valueStart++;
                    }

                    // Find end of token
                    int tokenEnd = valueStart;
                    while (tokenEnd < jsonResponse.length()) {
                        char c = jsonResponse.charAt(tokenEnd);
                        if (c == '"' || c == ',' || c == '}') {
                            break;
                        }
                        tokenEnd++;
                    }

                    if (tokenEnd > valueStart) {
                        String token = jsonResponse.substring(valueStart, tokenEnd).trim();
                        if (!token.isEmpty() && token.length() > 10) {
                            api.logging().logToOutput("[EXTRACT-JSON] Found JWT: " +
                                    token.substring(0, Math.min(30, token.length())) + "...");
                            return token;
                        }
                    }
                }
            }

            api.logging().logToError("[EXTRACT-JSON] No JWT found in response");
            return null;

        } catch (Exception e) {
            api.logging().logToError("[EXTRACT-JSON] Exception: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Method to extract JWT from authentication response
    private String extractJWT(HttpResponse response) {
        api.logging().logToOutput("[EXTRACT] Starting JWT extraction from auth response");

        try {
            // Try to extract JWT from Authorization header in response
            String authHeader = response.headerValue("Authorization");
            api.logging().logToOutput("[EXTRACT] Authorization header: " + (authHeader != null ? authHeader : "null"));
            if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ") && authHeader.length() > 7) {
                String token = authHeader.substring(7).trim();
                if (!token.isEmpty()) {
                    api.logging().logToOutput("[EXTRACT] Found JWT in Authorization header: " + token.substring(0, Math.min(30, token.length())) + "...");
                    return token;
                }
            }

            // Try to extract from Set-Cookie header
            String setCookieHeader = response.headerValue("Set-Cookie");
            api.logging().logToOutput("[EXTRACT] Set-Cookie header: " + (setCookieHeader != null ? setCookieHeader : "null"));
            if (setCookieHeader != null && setCookieHeader.contains("token=")) {
                try {
                    int tokenStartIndex = setCookieHeader.indexOf("token=");
                    if (tokenStartIndex != -1 && tokenStartIndex + 6 < setCookieHeader.length()) {
                        int tokenStart = tokenStartIndex + 6;
                        int tokenEnd = setCookieHeader.indexOf(";", tokenStart);
                        if (tokenEnd == -1) {
                            tokenEnd = setCookieHeader.length();
                        }
                        if (tokenEnd > tokenStart) {
                            String token = setCookieHeader.substring(tokenStart, tokenEnd).trim();
                            if (!token.isEmpty() && token.length() > 10) {
                                api.logging().logToOutput("[EXTRACT] Found JWT in Set-Cookie: " + token.substring(0, Math.min(30, token.length())) + "...");
                                return token;
                            }
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("[EXTRACT] Error parsing Set-Cookie: " + e.getMessage());
                }
            }

            // Try to extract from response body (JSON)
            String responseBody = response.bodyToString();
            api.logging().logToOutput("[EXTRACT] Checking response body for JWT patterns");

            if (responseBody != null && !responseBody.trim().isEmpty()) {
                // Use the configured token property name as the primary pattern
                String primaryPattern = "\"" + tokenPropertyName + "\":";

                // Keep fallback patterns for compatibility, but prioritize the configured one
                String[] patterns = {
                        primaryPattern, // Use configured token property first
                        "\"token\":", "\"access_token\":", "\"jwt\":", "\"accessToken\":",
                        "'token':", "'access_token':", "'" + tokenPropertyName + "':"
                };

                api.logging().logToOutput("[EXTRACT] Primary token property: " + tokenPropertyName);

                for (String pattern : patterns) {
                    try {
                        api.logging().logToOutput("[EXTRACT] Checking pattern: " + pattern);
                        int tokenStart = responseBody.indexOf(pattern);
                        if (tokenStart != -1) {
                            api.logging().logToOutput("[EXTRACT] Found pattern at position: " + tokenStart);

                            // Find the start of the token value (after the colon and optional whitespace)
                            int valueStart = tokenStart + pattern.length();

                            // Safe bounds checking for whitespace/colon skipping
                            while (valueStart < responseBody.length() &&
                                    (responseBody.charAt(valueStart) == ' ' || responseBody.charAt(valueStart) == ':')) {
                                valueStart++;
                            }

                            // Skip opening quote if present (with bounds check)
                            if (valueStart < responseBody.length() &&
                                    (responseBody.charAt(valueStart) == '"' || responseBody.charAt(valueStart) == '\'')) {
                                valueStart++;
                            }

                            // Find the end of the token value (with bounds check)
                            int tokenEnd = valueStart;
                            while (tokenEnd < responseBody.length()) {
                                char c = responseBody.charAt(tokenEnd);
                                if (c == '"' || c == '\'' || c == ',' || c == '}' || c == '\n' || c == '\r') {
                                    break;
                                }
                                tokenEnd++;
                            }

                            // Safe substring extraction with bounds validation
                            if (tokenEnd > valueStart && valueStart < responseBody.length() && tokenEnd <= responseBody.length()) {
                                String token = responseBody.substring(valueStart, tokenEnd).trim();
                                if (!token.isEmpty() && token.length() > 10) { // Basic validation
                                    api.logging().logToOutput("[EXTRACT] Found JWT in response body with pattern " + pattern + ": " +
                                            token.substring(0, Math.min(30, token.length())) + "...");
                                    return token;
                                }
                            }
                        }
                    } catch (Exception patternException) {
                        api.logging().logToError("[EXTRACT] Error processing pattern '" + pattern + "': " + patternException.getMessage());
                        continue; // Try next pattern
                    }
                }
            }

            api.logging().logToError("[EXTRACT] No JWT found in response. Response body: " +
                    (responseBody != null && responseBody.length() > 200 ? responseBody.substring(0, 200) + "..." : responseBody));

            // Return null if no JWT found
            return null;

        } catch (Exception e) {
            api.logging().logToError("[EXTRACT] Exception during JWT extraction: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Method to trigger re-authentication and update vault (called on 401 responses)
    private void triggerReAuthentication() {
        api.logging().logToOutput("[RE-AUTH] Triggering re-authentication due to 401 response");

        try {
            // Step 1: Get new JWT from auth server
            String newJWT = callAuthUrl();

            if (newJWT != null && !newJWT.trim().isEmpty()) {
                // Step 2: Clear the vault (remove old invalid token)
                clearJWTVault();
                
                // Step 3: Store new JWT in vault for future use
                storeJWTInVault(newJWT);
                api.logging().logToOutput("[RE-AUTH] Successfully obtained and stored new JWT in vault");
            } else {
                api.logging().logToError("[RE-AUTH] Failed to obtain new JWT");
                // Clear vault if we couldn't get a new JWT
                clearJWTVault();
                api.logging().logToError("[RE-AUTH] Vault cleared due to authentication failure");
            }
        } catch (Exception e) {
            api.logging().logToError("[RE-AUTH] Exception during re-authentication: " + e.getMessage());
            e.printStackTrace();
            // Clear vault on exception
            clearJWTVault();
        }
    }

    // Method to check if a request is an authentication request
    private boolean isAuthenticationRequest(String url) {
        if (url == null) {
            return false;
        }
        
        // Check if URL matches configured auth URL
        if (authUrl != null && !authUrl.trim().isEmpty() && url.contains(authUrl)) {
            return true;
        }
        
        // Check for common auth endpoints
        String lowerUrl = url.toLowerCase();
        return lowerUrl.contains("/auth") || 
               lowerUrl.contains("/login") || 
               lowerUrl.contains("/signin") ||
               lowerUrl.contains("/authenticate");
    }

    // Method to call the auth URL and get a new JWT
    private String callAuthUrl() {
        try {
            api.logging().logToOutput("[AUTH] Starting JWT authentication process...");
            api.logging().logToOutput("[AUTH] Using SAVED configuration:");
            api.logging().logToOutput("[AUTH] Auth URL: " + authUrl);
            api.logging().logToOutput("[AUTH] Username: " + username);
            api.logging().logToOutput("[AUTH] Token Property: " + tokenPropertyName);

            // Validate configuration
            if (authUrl == null || authUrl.trim().isEmpty()) {
                api.logging().logToError("[AUTH] Auth URL is empty - cannot authenticate");
                return null;
            }

            // Use saved configuration values
            String method = savedHttpMethod;
            String body = savedRequestBody
                    .replace("[USERNAME]", username)
                    .replace("[PASSWORD]", password);

            api.logging().logToOutput("[AUTH] HTTP Method: " + method);
            api.logging().logToOutput("[AUTH] Request body: " + body);

            // Use SimpleHttpClient for the request
            SimpleHttpClient httpClient = new SimpleHttpClient(api);
            httpClient.setUseJavaFallback(useJavaHttpFallback);
            HttpResponse response = null;

            if ("POST".equals(method)) {
                // Send POST request
                response = httpClient.sendPostRequest(authUrl, body, null);

                // If Burp API failed, try Java fallback if enabled
                if (response == null) {
                    if (useJavaHttpFallback) {
                        api.logging().logToOutput("[AUTH] Burp API failed, using Java HTTP fallback");
                        String javaResponse = httpClient.sendPostWithJavaHttp(authUrl, body);
                        if (javaResponse != null) {
                            // Extract JWT directly from JSON response
                            return extractJWTFromJson(javaResponse);
                        } else {
                            api.logging().logToError("[AUTH] Java HTTP fallback also failed");
                            return null;
                        }
                    } else {
                        api.logging().logToError("[AUTH] Burp API failed and Java HTTP fallback is DISABLED");
                        api.logging().logToError("[AUTH] Enable 'Use Java HTTP Fallback' in settings if experiencing timeouts");
                        return null;
                    }
                }
            } else if ("GET".equals(method)) {
                // For GET requests, convert body to query parameters
                String queryParams = convertBodyToQueryParams(body);
                String getUrl = authUrl;
                if (queryParams != null && !queryParams.isEmpty()) {
                    // Add query parameters to URL
                    if (authUrl.contains("?")) {
                        getUrl = authUrl + "&" + queryParams;
                    } else {
                        getUrl = authUrl + "?" + queryParams;
                    }
                }
                api.logging().logToOutput("[AUTH] GET URL with params: " + getUrl);
                
                // Send GET request
                response = httpClient.sendGetRequest(getUrl, null);
            } else {
                api.logging().logToError("[AUTH] Unsupported HTTP method: " + method);
                return null;
            }

            // Check response
            if (response == null) {
                api.logging().logToError("[AUTH] Failed to get response from auth server");
                return null;
            }

            api.logging().logToOutput("[AUTH] Auth response status: " + response.statusCode());

            // Check if response is successful
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                String extractedJWT = extractJWT(response);
                if (extractedJWT != null && !extractedJWT.trim().isEmpty()) {
                    api.logging().logToOutput("[AUTH] Successfully extracted JWT: " + extractedJWT.substring(0, Math.min(30, extractedJWT.length())) + "...");
                    return extractedJWT;
                } else {
                    api.logging().logToError("[AUTH] No JWT found in successful response");
                    return null;
                }
            } else {
                api.logging().logToError("[AUTH] Failed to authenticate. Status code: " + response.statusCode());
                String responseBody = response.bodyToString();
                api.logging().logToError("[AUTH] Response body: " + responseBody);
                return null;
            }
        } catch (Exception e) {
            api.logging().logToError("[AUTH] Exception during authentication: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Extract JWT from Authorization header in requests
    private String extractJWTFromRequest(HttpRequest request) {
        try {
            String authHeader = request.headerValue("Authorization");
            api.logging().logToOutput("[JWT Extract] Authorization header: " + (authHeader != null ? "Found: " + authHeader.substring(0, Math.min(20, authHeader.length())) + "..." : "Not found"));

            if (authHeader != null && authHeader.length() > 7) {
                if (authHeader.toLowerCase().startsWith("bearer ")) {
                    String jwt = authHeader.substring(7).trim();
                    if (!jwt.isEmpty() && jwt.length() > 10) {
                        api.logging().logToOutput("[JWT Extract] Found Bearer token: " + jwt.substring(0, Math.min(30, jwt.length())) + "...");
                        return jwt;
                    }
                }
            }

            api.logging().logToOutput("[JWT Extract] No Bearer token found");
            return null;
        } catch (Exception e) {
            api.logging().logToError("[JWT Extract] Error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Store request-response pairs for later viewing
    private java.util.Map<Integer, APICallData> requestResponseMap = new java.util.concurrent.ConcurrentHashMap<>();

    // Store pending requests that are waiting for responses
    private java.util.Map<String, Integer> pendingRequests = new java.util.concurrent.ConcurrentHashMap<>();
    // Changed to store list of unique keys per host+path to handle concurrent requests to same endpoint
    private java.util.Map<String, java.util.List<String>> requestIdentifiers = new java.util.concurrent.ConcurrentHashMap<>();

    // Update response data for an existing request
    private void updateRequestWithResponse(String hostAndUrl, String responseData, int statusCode, String status) {
        api.logging().logToOutput("[UPDATE-RESPONSE] Looking for request matching: " + hostAndUrl + " with status: " + statusCode);
        
        // Get list of unique keys for this host+url combination (handles concurrent requests)
        java.util.List<String> uniqueKeys = requestIdentifiers.get(hostAndUrl);
        if (uniqueKeys != null && !uniqueKeys.isEmpty()) {
            api.logging().logToOutput("[UPDATE-RESPONSE] Found " + uniqueKeys.size() + " pending request(s) for: " + hostAndUrl);
            
            // Try each unique key until we find one that matches
            for (String uniqueKey : new ArrayList<>(uniqueKeys)) {
                Integer requestId = pendingRequests.get(uniqueKey);
                if (requestId != null) {
                    api.logging().logToOutput("[UPDATE-RESPONSE] Trying unique key: " + uniqueKey + " -> request ID: " + requestId);
                    APICallData apiCall = requestResponseMap.get(requestId);
                    if (apiCall != null) {
                        // Update the stored data immediately
                        apiCall.setResponseData(responseData);
                        apiCall.setStatusCode(statusCode);
                        
                        SwingUtilities.invokeLater(() -> {
                            // Update table model (find the row and refresh it)
                            for (int i = 0; i < apiCallTableModel.getRowCount(); i++) {
                                if ((Integer) apiCallTableModel.getValueAt(i, 0) == requestId) {
                                    // Update status to show the HTTP response code
                                    apiCallTableModel.setValueAt(String.valueOf(statusCode), i, 3);
                                    // Force table refresh
                                    apiCallTableModel.fireTableRowsUpdated(i, i);
                                    break;
                                }
                            }

                            api.logging().logToOutput("Updated request #" + requestId + " with response data (status: " + statusCode + ")");
                        });
                        
                        // Clean up after processing
                        pendingRequests.remove(uniqueKey);
                        uniqueKeys.remove(uniqueKey);
                        
                        // If no more keys for this host+url, remove the entry
                        if (uniqueKeys.isEmpty()) {
                            requestIdentifiers.remove(hostAndUrl);
                        }
                        
                        // Successfully matched and updated
                        return;
                    }
                }
            }
            
            api.logging().logToError("[UPDATE-RESPONSE] Could not find matching request for any unique keys");
        } else {
            api.logging().logToOutput("[WARNING] No pending request found for: " + hostAndUrl);
            api.logging().logToOutput("[WARNING] Current requestIdentifiers keys: " + requestIdentifiers.keySet());
            
            // Debug: Check what's in our tracking maps
            api.logging().logToOutput("[DEBUG] Current pendingRequests size: " + pendingRequests.size());
            api.logging().logToOutput("[DEBUG] Current requestResponseMap size: " + requestResponseMap.size());
            
            // Try a more flexible match by looking through all pending requests
            for (Map.Entry<String, Integer> entry : pendingRequests.entrySet()) {
                if (entry.getKey().startsWith(hostAndUrl + "_")) {
                    api.logging().logToOutput("[UPDATE-RESPONSE] Found pending request with flexible match: " + entry.getKey());
                    Integer requestId = entry.getValue();
                    APICallData apiCall = requestResponseMap.get(requestId);
                    if (apiCall != null) {
                        // Update the stored data immediately
                        apiCall.setResponseData(responseData);
                        apiCall.setStatusCode(statusCode);
                        
                        SwingUtilities.invokeLater(() -> {
                            // Update table model
                            for (int i = 0; i < apiCallTableModel.getRowCount(); i++) {
                                if ((Integer) apiCallTableModel.getValueAt(i, 0) == requestId) {
                                    apiCallTableModel.setValueAt(String.valueOf(statusCode), i, 3);
                                    apiCallTableModel.fireTableRowsUpdated(i, i);
                                    break;
                                }
                            }
                            api.logging().logToOutput("Updated request #" + requestId + " with response (flexible match)");
                        });
                        // Clean up
                        pendingRequests.remove(entry.getKey());
                        break;
                    }
                }
            }
        }
    }

    // Create dark mode table with sorting
    private JScrollPane createApiCallsTable() {
        apiCallsTable = new JTable(apiCallTableModel);

        // Create and set the table sorter
        tableSorter = new TableRowSorter<>(apiCallTableModel);
        apiCallsTable.setRowSorter(tableSorter);

        // Configure sorting for # column (integer sorting)
        tableSorter.setComparator(0, new Comparator<Integer>() {
            @Override
            public int compare(Integer o1, Integer o2) {
                return o1.compareTo(o2);
            }
        });

        // Apply consistent theme styling
        ThemeManager.styleTable(apiCallsTable);

        // Configure header border
        apiCallsTable.getTableHeader().setBorder(BorderFactory.createEmptyBorder());

        // Set column widths
        apiCallsTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // #
        apiCallsTable.getColumnModel().getColumn(1).setPreferredWidth(200); // Host
        apiCallsTable.getColumnModel().getColumn(2).setPreferredWidth(80);  // Type
        apiCallsTable.getColumnModel().getColumn(3).setPreferredWidth(120); // Status
        apiCallsTable.getColumnModel().getColumn(4).setPreferredWidth(60);  // Risk
        apiCallsTable.getColumnModel().getColumn(5).setPreferredWidth(80);  // Found
        apiCallsTable.getColumnModel().getColumn(6).setPreferredWidth(120); // Expires (wider for time display)
        apiCallsTable.getColumnModel().getColumn(7).setPreferredWidth(80);  // Actions

        // Custom renderer for Actions column
        apiCallsTable.getColumnModel().getColumn(7).setCellRenderer(new ActionButtonRenderer());
        apiCallsTable.getColumnModel().getColumn(7).setCellEditor(new ActionButtonEditor(new JCheckBox(), apiCallTableModel));

        // Add double-click listener
        apiCallsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = apiCallsTable.getSelectedRow();
                    if (row != -1) {
                        // Convert view row to model row for sorting
                        int modelRow = apiCallsTable.convertRowIndexToModel(row);
                        APICallData apiCallData = apiCallTableModel.getAPICallData(modelRow);
                        if (apiCallData != null) {
                            // Open request/response viewer
                            SwingUtilities.invokeLater(() -> {
                                RequestResponseViewer viewer = new RequestResponseViewer(
                                        (JFrame) SwingUtilities.getWindowAncestor(apiCallsTable),
                                        apiCallData
                                );
                                viewer.setVisible(true);
                            });
                        }
                    }
                }
            }
        });

        // Add right-click context menu
        JPopupMenu contextMenu = new JPopupMenu();
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
        JMenuItem viewDetails = new JMenuItem("View Request/Response");
        JMenuItem debugData = new JMenuItem("[DEBUG] Show Stored Data");

        sendToRepeater.addActionListener(e -> {
            int row = apiCallsTable.getSelectedRow();
            if (row != -1) {
                int modelRow = apiCallsTable.convertRowIndexToModel(row);
                APICallData apiCallData = apiCallTableModel.getAPICallData(modelRow);
                if (apiCallData != null) {
                    sendRequestToRepeater(apiCallData);
                }
            }
        });

        sendToIntruder.addActionListener(e -> {
            int row = apiCallsTable.getSelectedRow();
            if (row != -1) {
                int modelRow = apiCallsTable.convertRowIndexToModel(row);
                APICallData apiCallData = apiCallTableModel.getAPICallData(modelRow);
                if (apiCallData != null) {
                    sendRequestToIntruder(apiCallData);
                }
            }
        });

        viewDetails.addActionListener(e -> {
            int row = apiCallsTable.getSelectedRow();
            if (row != -1) {
                int modelRow = apiCallsTable.convertRowIndexToModel(row);
                APICallData apiCallData = apiCallTableModel.getAPICallData(modelRow);
                if (apiCallData != null) {
                    SwingUtilities.invokeLater(() -> {
                        RequestResponseViewer viewer = new RequestResponseViewer(
                                (JFrame) SwingUtilities.getWindowAncestor(apiCallsTable),
                                apiCallData
                        );
                        viewer.setVisible(true);
                    });
                }
            }
        });

        debugData.addActionListener(e -> {
            int row = apiCallsTable.getSelectedRow();
            if (row != -1) {
                int modelRow = apiCallsTable.convertRowIndexToModel(row);
                APICallData apiCallData = apiCallTableModel.getAPICallData(modelRow);
                if (apiCallData != null) {
                    // Show debug information in a dialog
                    String debugInfo = "[DEBUG] Stored Data for Request #" + apiCallData.getId() + "\n\n" +
                            "Host: '" + apiCallData.getHost() + "'\n" +
                            "URL: '" + apiCallData.getUrl() + "'\n" +
                            "Method: '" + apiCallData.getMethod() + "'\n" +
                            "Type: '" + apiCallData.getType() + "'\n" +
                            "Status: '" + apiCallData.getStatus() + "'\n" +
                            "Risk: '" + apiCallData.getRisk() + "'\n" +
                            "Expires: '" + apiCallData.getExpires() + "'\n" +
                            "Status Code: " + apiCallData.getStatusCode() + "\n" +
                            "Extracted JWT: " + (apiCallData.getExtractedJWT() != null && !apiCallData.getExtractedJWT().isEmpty() ?
                            apiCallData.getExtractedJWT().substring(0, Math.min(50, apiCallData.getExtractedJWT().length())) + "..." : "None") + "\n\n" +
                            "Request Data Length: " + (apiCallData.getRequestData() != null ? apiCallData.getRequestData().length() : "null") + "\n" +
                            "Response Data Length: " + (apiCallData.getResponseData() != null ? apiCallData.getResponseData().length() : "null");

                    // Also log to Burp output
                    api.logging().logToOutput(debugInfo);

                    JTextArea textArea = new JTextArea(debugInfo, 15, 50);
                    textArea.setEditable(false);
                    textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
                    JScrollPane scrollPane = new JScrollPane(textArea);
                    JOptionPane.showMessageDialog(apiCallsTable, scrollPane, "Debug: Stored Data", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        contextMenu.add(sendToRepeater);
        contextMenu.add(sendToIntruder);
        contextMenu.addSeparator();
        contextMenu.add(viewDetails);
        contextMenu.addSeparator();
        contextMenu.add(debugData);

        // Add right-click handler
        apiCallsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e);
                }
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e);
                }
            }

            private void showContextMenu(java.awt.event.MouseEvent e) {
                int row = apiCallsTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    apiCallsTable.setRowSelectionInterval(row, row);
                    contextMenu.show(apiCallsTable, e.getX(), e.getY());
                }
            }
        });

        // Create scroll pane with theme support
        JScrollPane scrollPane = new JScrollPane(apiCallsTable);
        ThemeManager.styleScrollPane(scrollPane);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());

        return scrollPane;
    }

    // Helper methods using HttpFormatter utility class
    private String formatHttpRequest(HttpRequest request) {
        return HttpFormatter.formatRequest(request);
    }

    private String formatHttpResponse(HttpResponse response) {
        return HttpFormatter.formatResponse(response);
    }

    // Method to send request to Burp Repeater
    private void sendRequestToRepeater(APICallData apiCallData) {
        try {
            api.logging().logToOutput("[REPEATER] Attempting to send request #" + apiCallData.getId() + " to Repeater");
            api.logging().logToOutput("[REPEATER] Host: " + apiCallData.getHost() + ", URL: " + apiCallData.getUrl() + ", Method: " + apiCallData.getMethod());

            // Parse the stored request data back into an HttpRequest
            HttpRequest request = parseStoredRequest(apiCallData);
            if (request != null) {
                // Send to Repeater with a custom tab name
                String tabName = "JWT-" + apiCallData.getHost() + "-" + apiCallData.getId();
                api.repeater().sendToRepeater(request, tabName);
                api.logging().logToOutput("[REPEATER] Successfully sent request #" + apiCallData.getId() + " to Repeater: " + tabName);
            } else {
                api.logging().logToError("[REPEATER] Failed to parse request for Repeater - request object is null");
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(apiCallsTable,
                            "Failed to parse request data. Check logs for details.",
                            "Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        } catch (Exception e) {
            api.logging().logToError("[REPEATER] Error sending to Repeater: " + e.getMessage());
            e.printStackTrace();
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(apiCallsTable,
                        "Error sending to Repeater: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            });
        }
    }

    // Method to send request to Burp Intruder
    private void sendRequestToIntruder(APICallData apiCallData) {
        try {
            api.logging().logToOutput("[INTRUDER] Attempting to send request #" + apiCallData.getId() + " to Intruder");
            api.logging().logToOutput("[INTRUDER] Host: " + apiCallData.getHost() + ", URL: " + apiCallData.getUrl() + ", Method: " + apiCallData.getMethod());

            // Parse the stored request data back into an HttpRequest
            HttpRequest request = parseStoredRequest(apiCallData);
            if (request != null) {
                // Send to Intruder
                api.intruder().sendToIntruder(request);
                api.logging().logToOutput("[INTRUDER] Successfully sent request #" + apiCallData.getId() + " to Intruder");
            } else {
                api.logging().logToError("[INTRUDER] Failed to parse request for Intruder - request object is null");
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(apiCallsTable,
                            "Failed to parse request data. Check logs for details.",
                            "Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        } catch (Exception e) {
            api.logging().logToError("[INTRUDER] Error sending to Intruder: " + e.getMessage());
            e.printStackTrace();
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(apiCallsTable,
                        "Error sending to Intruder: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            });
        }
    }

    // Helper method to parse stored request data back into HttpRequest
    private HttpRequest parseStoredRequest(APICallData apiCallData) {
        try {
            api.logging().logToOutput("[PARSE] Starting to parse stored request for #" + apiCallData.getId());

            // First try to use the original HttpRequest object if available
            HttpRequest originalRequest = apiCallData.getOriginalRequest();
            if (originalRequest != null) {
                api.logging().logToOutput("[PARSE] Using stored original HttpRequest object");

                // Update the JWT token if we have one in the vault
                String jwtFromVault = getJWTFromVault();
                if (!isVaultEmpty()) {
                    HttpRequest updatedRequest = originalRequest.withHeader(jwtHeaderName, jwtPrefix + jwtFromVault);
                    api.logging().logToOutput("[PARSE] Updated Authorization header with vault JWT");
                    return updatedRequest;
                } else {
                    api.logging().logToOutput("[PARSE] Vault is empty - using original request as-is");
                    return originalRequest;
                }
            }

            // If no original request stored, fall back to basic reconstruction
            api.logging().logToOutput("[PARSE] No original HttpRequest stored, falling back to basic reconstruction");
            return createBasicRequest(apiCallData);

        } catch (Exception e) {
            api.logging().logToError("[PARSE] Exception in parseStoredRequest: " + e.getMessage());
            e.printStackTrace();
            // Fall back to basic reconstruction on any error
            return createBasicRequest(apiCallData);
        }
    }

    // Helper method to create a basic request when full parsing fails
    private HttpRequest createBasicRequest(APICallData apiCallData) {
        try {
            String url = apiCallData.getUrl();
            String method = apiCallData.getMethod();
            String host = apiCallData.getHost();

            // Validate required data for basic reconstruction
            if (host == null || host.trim().isEmpty() ||
                    url == null || url.trim().isEmpty() ||
                    method == null || method.trim().isEmpty()) {
                api.logging().logToError("[PARSE] Missing required data for basic reconstruction");
                return null;
            }

            // The URL from requestToBeSent.url() is already a full URL, so use it directly
            String fullUrl = url;

            // Only construct if it's not already a full URL (fallback case)
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                if (!url.startsWith("/")) {
                    url = "/" + url;
                }
                fullUrl = "https://" + host + url;
                api.logging().logToOutput("[PARSE] Constructed full URL from relative path: " + fullUrl);
            } else {
                api.logging().logToOutput("[PARSE] Using stored full URL: " + fullUrl);
            }

            // Create basic request
            HttpRequest baseRequest = HttpRequest.httpRequest(fullUrl)
                    .withMethod(method.toUpperCase());

            api.logging().logToOutput("[PARSE] Created basic request with method: " + method.toUpperCase());

            // Add Authorization header using JWT from vault if available
            String jwtFromVault = getJWTFromVault();
            if (!isVaultEmpty()) {
                String authHeaderValue = jwtPrefix + jwtFromVault;
                baseRequest = baseRequest.withHeader(jwtHeaderName, authHeaderValue);
                api.logging().logToOutput("[PARSE] Added JWT header from vault: " + jwtHeaderName + ": " + jwtPrefix + "[VAULT_JWT_TOKEN]");
            } else {
                api.logging().logToOutput("[PARSE] Vault is empty, not adding auth header");
            }

            // Add common headers
            baseRequest = baseRequest.withHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            baseRequest = baseRequest.withHeader("Accept", "application/json, text/plain, */*");
            baseRequest = baseRequest.withHeader("Cache-Control", "no-cache");

            api.logging().logToOutput("[PARSE] Successfully created basic HttpRequest object");
            return baseRequest;

        } catch (Exception e) {
            api.logging().logToError("[PARSE] Exception in createBasicRequest: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Create UI components
    public JPanel getUI() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());

        // Create configuration panel
        JPanel configPanel = createConfigurationPanel();

        // Create monitoring panel
        JPanel monitoringPanel = createMonitoringPanel();

        // Create main horizontal split pane
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, configPanel, monitoringPanel);
        mainSplitPane.setDividerLocation(600); // Initial position
        mainSplitPane.setResizeWeight(0.4); // Give 40% to config, 60% to monitoring
        mainSplitPane.setContinuousLayout(true);
        mainSplitPane.setOneTouchExpandable(true);

        mainPanel.add(mainSplitPane, BorderLayout.CENTER);

        return mainPanel;
    }

    private JPanel createConfigurationPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Configuration"));

        // Create single consolidated API configuration panel
        JPanel apiConfigPanel = createConsolidatedApiConfigurationPanel();
        JPanel buttonPanel = createButtonPanel();

        panel.add(apiConfigPanel, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createConsolidatedApiConfigurationPanel() {
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("API Configuration"));

        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 8, 5, 8);
        c.anchor = GridBagConstraints.WEST;
        
        int currentRow = 0;

        // Row 0: Extension Enabled checkbox
        enabledCheckbox = new JCheckBox("Extension Enabled", enabled);
        enabledCheckbox.addActionListener(e -> {
            enabled = enabledCheckbox.isSelected();
            api.logging().logToOutput("Extension enabled status changed to: " + enabled);
        });
        c.gridx = 0;
        c.gridy = currentRow++;
        c.gridwidth = 2;
        c.weightx = 1.0;
        configPanel.add(enabledCheckbox, c);



        // Row 1: Login API URL
        JLabel authUrlLabel = new JLabel("Login API URL:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 1;
        c.weightx = 0.0;
        configPanel.add(authUrlLabel, c);

        authUrlField = new JTextField(authUrl, 50);
        c.gridx = 1;
        c.gridy = currentRow++;
        c.gridwidth = 1;
        c.weightx = 1.0;
        configPanel.add(authUrlField, c);

        // Row 2: Username
        JLabel usernameLabel = new JLabel("Username:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 1;
        c.weightx = 0.0;
        configPanel.add(usernameLabel, c);

        usernameField = new JTextField(username, 20);
        c.gridx = 1;
        c.gridy = currentRow++;
        c.gridwidth = 1;
        c.weightx = 1.0;
        configPanel.add(usernameField, c);

        // Row 3: Password
        JLabel passwordLabel = new JLabel("Password:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 1;
        c.weightx = 0.0;
        configPanel.add(passwordLabel, c);

        passwordField = new JTextField(password, 20);
        c.gridx = 1;
        c.gridy = currentRow++;
        c.gridwidth = 1;
        c.weightx = 1.0;
        configPanel.add(passwordField, c);

        // Row 4: HTTP Method
        JLabel methodLabel = new JLabel("HTTP Method:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 1;
        c.weightx = 0.0;
        configPanel.add(methodLabel, c);

        httpMethodCombo = new JComboBox<>(new String[]{"POST", "GET", "PUT"});
        c.gridx = 1;
        c.gridy = currentRow++;
        c.gridwidth = 1;
        c.weightx = 1.0;
        configPanel.add(httpMethodCombo, c);

        // Row 5: Content-Type
        JLabel contentTypeLabel = new JLabel("Content-Type:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 1;
        c.weightx = 0.0;
        configPanel.add(contentTypeLabel, c);

        contentTypeField = new JTextField("application/json", 20);
        c.gridx = 1;
        c.gridy = currentRow++;
        c.gridwidth = 1;
        c.weightx = 1.0;
        configPanel.add(contentTypeField, c);

        // Row 6: JWT Header Name
        JLabel jwtHeaderLabel = new JLabel("JWT Header Name:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 1;
        c.weightx = 0.0;
        configPanel.add(jwtHeaderLabel, c);

        jwtHeaderField = new JTextField(jwtHeaderName, 20);
        c.gridx = 1;
        c.gridy = currentRow++;
        c.gridwidth = 1;
        c.weightx = 1.0;
        configPanel.add(jwtHeaderField, c);

        // Row 7: JWT Prefix
        JLabel jwtPrefixLabel = new JLabel("JWT Prefix:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 1;
        c.weightx = 0.0;
        configPanel.add(jwtPrefixLabel, c);

        jwtPrefixField = new JTextField(jwtPrefix, 15);
        c.gridx = 1;
        c.gridy = currentRow++;
        c.gridwidth = 1;
        c.weightx = 1.0;
        configPanel.add(jwtPrefixField, c);

        // Row 8: Token Property
        JLabel tokenPropertyLabel = new JLabel("Token Property:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 1;
        c.weightx = 0.0;
        configPanel.add(tokenPropertyLabel, c);

        tokenPropertyField = new JTextField(tokenPropertyName, 30);
        tokenPropertyField.setToolTipText("JSON property name containing the JWT token (e.g., 'token', 'access_token', 'jwt')");
        c.gridx = 1;
        c.gridy = currentRow++;
        c.gridwidth = 1;
        c.weightx = 1.0;
        configPanel.add(tokenPropertyField, c);

        // Row 9: Request Body label
        JLabel bodyLabel = new JLabel("Request Body:");
        c.gridx = 0;
        c.gridy = currentRow;
        c.gridwidth = 2;
        c.weightx = 0.0;
        configPanel.add(bodyLabel, c);

        // Row 10: Request Body (full width)
        requestBodyArea = new JTextArea("{\"username\":\"[USERNAME]\",\"password\":\"[PASSWORD]\"}");
        requestBodyArea.setRows(6);
        ThemeManager.styleMonospaceTextArea(requestBodyArea);
        JScrollPane scrollPane = new JScrollPane(requestBodyArea);
        scrollPane.setPreferredSize(new Dimension(600, 150));
        c.gridx = 0;
        c.gridy = ++currentRow;
        c.gridwidth = 2;
        c.weighty = 0.3;
        c.fill = GridBagConstraints.BOTH;
        configPanel.add(scrollPane, c);

        // Row 11: Current JWT Vault label
        JLabel currentJwtLabel = new JLabel("JWT Vault:");
        c.gridx = 0;
        c.gridy = ++currentRow;
        c.gridwidth = 2;
        c.weighty = 0.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        configPanel.add(currentJwtLabel, c);

        // Row 12: Current JWT Vault display (full width)
        currentJwtArea = new JTextArea(4, 30);
        currentJwtArea.setEditable(false);
        currentJwtArea.setText(jwtVault.isEmpty() ? "Vault: EMPTY\n\nNo JWT available for injection" : "Vault: " + jwtVault + "\n\nExpires: " + getJWTExpirationTime(jwtVault));
        ThemeManager.styleMonospaceTextArea(currentJwtArea);
        currentJwtArea.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        currentJwtArea.setLineWrap(true);
        currentJwtArea.setWrapStyleWord(true);
        currentJwtArea.setOpaque(true);

        JScrollPane jwtScrollPane = new JScrollPane(currentJwtArea);
        jwtScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        ThemeManager.styleScrollPane(jwtScrollPane);
        jwtScrollPane.setPreferredSize(new Dimension(600, 120));
        c.gridx = 0;
        c.gridy = ++currentRow;
        c.gridwidth = 2;
        c.weighty = 0.3;
        c.fill = GridBagConstraints.BOTH;
        configPanel.add(jwtScrollPane, c);

        return configPanel;
    }

    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton testLoginButton = new JButton("Test Login");
        JButton previewRequestButton = new JButton("Preview Request");
        JButton clearJwtButton = new JButton("Clear Vault");
        JButton saveConfigButton = new JButton("Save Configuration");

        buttonPanel.add(testLoginButton);
        buttonPanel.add(previewRequestButton);
        buttonPanel.add(clearJwtButton);
        buttonPanel.add(saveConfigButton);

        // Add action listeners to buttons
        testLoginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                api.logging().logToOutput("[TEST] Starting test login with current configuration...");

                // Update the token property name from UI before testing
                tokenPropertyName = tokenPropertyField.getText().trim();
                // Java HTTP fallback remains at default value (false for BApp Store compliance)

                try {
                    // Use the existing callAuthUrl method which has all the proper error handling
                    String newJWT = callAuthUrl();

                    if (newJWT != null && !newJWT.trim().isEmpty()) {
                        // Success!
                        api.logging().logToOutput("[TEST] Successfully extracted JWT: " + newJWT.substring(0, Math.min(30, newJWT.length())) + "...");

                        // Store the JWT in vault
                        storeJWTInVault(newJWT);

                        // Show success in logs only (no popup)
                        api.logging().logToOutput("[TEST] === TEST LOGIN SUCCESS ===");
                        api.logging().logToOutput("[TEST] JWT Successfully Retrieved and Stored in Vault");
                        api.logging().logToOutput("[TEST] Token: " + newJWT);
                        api.logging().logToOutput("[TEST] Expires: " + getJWTExpirationTime(newJWT));

                    } else {
                        // Failed to get JWT
                        api.logging().logToError("[TEST] Failed to extract JWT from auth response");

                        String errorText = "=== TEST LOGIN FAILED ===\n\n" +
                                "❌ No JWT token found in authentication response\n\n" +
                                "Check the extension output log for detailed error information.\n\n" +
                                "Common issues:\n" +
                                "• Authentication server is not running\n" +
                                "• Invalid credentials\n" +
                                "• Wrong Token Property name (currently: '" + tokenPropertyName + "')\n" +
                                "• Server returns JWT in unexpected format\n" +
                                "• Network connectivity issues";

                        JTextArea errorArea = new JTextArea(errorText, 15, 50);
                        errorArea.setEditable(false);
                        errorArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

                        JScrollPane errorScrollPane = new JScrollPane(errorArea);
                        JOptionPane.showMessageDialog(buttonPanel, errorScrollPane, "❌ Test Login - FAILED", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[TEST] Exception during test login: " + ex.getMessage());
                    ex.printStackTrace();

                    // Show exception popup
                    String exceptionText = "=== TEST LOGIN ERROR ===\n\n" +
                            "❌ Exception occurred during test login\n\n" +
                            "Error Type: " + ex.getClass().getSimpleName() + "\n" +
                            "Error Message: " + (ex.getMessage() != null ? ex.getMessage() : "Unknown error") + "\n\n" +
                            "Check the extension output log for full stack trace.";

                    JTextArea exceptionArea = new JTextArea(exceptionText, 10, 50);
                    exceptionArea.setEditable(false);
                    exceptionArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

                    JScrollPane exceptionScrollPane = new JScrollPane(exceptionArea);
                    JOptionPane.showMessageDialog(buttonPanel, exceptionScrollPane, "❌ Test Login - ERROR", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        previewRequestButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                api.logging().logToOutput("[PREVIEW] Generating request preview...");
                
                // Get current values from UI fields
                String previewUrl = authUrlField.getText().trim();
                String previewUsername = usernameField.getText().trim();
                String previewPassword = passwordField.getText().trim();
                String previewMethod = (String) httpMethodCombo.getSelectedItem();
                String previewContentType = contentTypeField.getText().trim();
                String previewBody = requestBodyArea.getText();
                String previewTokenProperty = tokenPropertyField.getText().trim();
                
                // Replace placeholders in body
                String finalBody = previewBody
                        .replace("[USERNAME]", previewUsername)
                        .replace("[PASSWORD]", previewPassword);
                
                // Build the preview request
                StringBuilder preview = new StringBuilder();
                preview.append(previewMethod).append(" ");
                
                // Parse URL to get path
                String path = "/";
                String host = "";
                String finalUrl = previewUrl;
                
                try {
                    if (previewUrl.startsWith("http://") || previewUrl.startsWith("https://")) {
                        java.net.URL url = new java.net.URL(previewUrl);
                        path = url.getPath().isEmpty() ? "/" : url.getPath();
                        if (url.getQuery() != null) {
                            path += "?" + url.getQuery();
                        }
                        host = url.getHost();
                        if (url.getPort() != -1 && url.getPort() != url.getDefaultPort()) {
                            host += ":" + url.getPort();
                        }
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[PREVIEW] Error parsing URL: " + ex.getMessage());
                }
                
                // For GET requests, convert body to query parameters
                if ("GET".equals(previewMethod)) {
                    String queryParams = convertBodyToQueryParams(finalBody);
                    if (queryParams != null && !queryParams.isEmpty()) {
                        if (path.contains("?")) {
                            path += "&" + queryParams;
                        } else {
                            path += "?" + queryParams;
                        }
                    }
                }
                
                preview.append(path).append(" HTTP/1.1\r\n");
                preview.append("Host: ").append(host).append("\r\n");
                
                // Add headers
                preview.append("Accept: */").append("*\r\n");
                preview.append("Accept-Language: en-US,en;q=0.9\r\n");
                preview.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n");
                
                if ("POST".equals(previewMethod) || "PUT".equals(previewMethod)) {
                    preview.append("Content-Type: ").append(previewContentType).append("\r\n");
                    preview.append("Content-Length: ").append(finalBody.length()).append("\r\n");
                }
                
                preview.append("Connection: close\r\n");
                preview.append("\r\n");
                
                if ("POST".equals(previewMethod) || "PUT".equals(previewMethod)) {
                    preview.append(finalBody);
                }
                
                // Create dialog to show preview
                JDialog previewDialog = new JDialog((JFrame) SwingUtilities.getWindowAncestor(buttonPanel), "Authentication Request Preview", true);
                previewDialog.setLayout(new BorderLayout());
                
                // Create info panel
                JPanel infoPanel = new JPanel(new GridBagLayout());
                GridBagConstraints c = new GridBagConstraints();
                c.insets = new Insets(5, 5, 5, 5);
                c.fill = GridBagConstraints.HORIZONTAL;
                
                // Add info labels
                c.gridx = 0; c.gridy = 0;
                infoPanel.add(new JLabel("This is the HTTP request that will be sent during authentication:"), c);
                
                c.gridy = 1;
                infoPanel.add(new JLabel("Token Property: '" + previewTokenProperty + "' (JWT will be extracted from this field in response)"), c);
                
                // Create text area for request preview
                JTextArea previewArea = new JTextArea(preview.toString());
                previewArea.setEditable(false);
                previewArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
                ThemeManager.styleMonospaceTextArea(previewArea);
                
                JScrollPane scrollPane = new JScrollPane(previewArea);
                scrollPane.setPreferredSize(new Dimension(800, 500));
                ThemeManager.styleScrollPane(scrollPane);
                
                // Add components to dialog
                previewDialog.add(infoPanel, BorderLayout.NORTH);
                previewDialog.add(scrollPane, BorderLayout.CENTER);
                
                // Add close button
                JPanel buttonPanelDialog = new JPanel(new FlowLayout());
                JButton closeButton = new JButton("Close");
                closeButton.addActionListener(ev -> previewDialog.dispose());
                buttonPanelDialog.add(closeButton);
                previewDialog.add(buttonPanelDialog, BorderLayout.SOUTH);
                
                // Show dialog
                previewDialog.pack();
                previewDialog.setLocationRelativeTo(buttonPanel);
                previewDialog.setVisible(true);
            }
        });

        clearJwtButton.addActionListener(e -> {
            clearJWTVault();
            api.logging().logToOutput("JWT vault cleared");
            JOptionPane.showMessageDialog(buttonPanel, "JWT vault cleared.");
        });

        saveConfigButton.addActionListener(e -> {
            updateConfig();
            JOptionPane.showMessageDialog(buttonPanel, "Configuration saved.");
        });

        return buttonPanel;
    }

    private JPanel createMonitoringPanel() {
        JPanel monitoringPanel = new JPanel(new BorderLayout());
        monitoringPanel.setBorder(BorderFactory.createTitledBorder("API Calls Monitor (Reactive Mode - In Scope Only)"));

        // Control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearButton = new JButton("Clear All");
        JLabel statusLabel = new JLabel("Monitoring API calls - Injecting JWT from vault when available...");

        clearButton.addActionListener(e -> {
            apiCallTableModel.clearAll();
            requestCounter = 0; // Reset counter when clearing
            api.logging().logToOutput("API calls table cleared");
        });

        controlPanel.add(clearButton);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(statusLabel);

        // Create table
        JScrollPane tableScrollPane = createApiCallsTable();

        // Create vertical split for controls and table
        JSplitPane monitoringSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, controlPanel, tableScrollPane);
        monitoringSplitPane.setDividerLocation(50); // Small space for controls
        monitoringSplitPane.setResizeWeight(0.0); // Keep controls at fixed size
        monitoringSplitPane.setContinuousLayout(true);

        monitoringPanel.add(monitoringSplitPane, BorderLayout.CENTER);

        return monitoringPanel;
    }

    // Update config from UI - ONLY called when Save Configuration is pressed
    private void updateConfig() {
        this.enabled = enabledCheckbox.isSelected();
        // useJavaHttpFallback remains at default value (false for BApp Store compliance)
        this.authUrl = authUrlField.getText().trim();
        this.username = usernameField.getText().trim();
        this.password = passwordField.getText().trim();
        this.jwtHeaderName = jwtHeaderField.getText().trim();
        this.jwtPrefix = jwtPrefixField.getText();
        this.tokenPropertyName = tokenPropertyField.getText().trim();

        // Save UI values to saved configuration fields
        this.savedHttpMethod = (String) httpMethodCombo.getSelectedItem();
        this.savedContentType = contentTypeField.getText().trim();
        this.savedRequestBody = requestBodyArea.getText();

        api.logging().logToOutput("Config SAVED - Enabled: " + enabled +
                ", Auth URL: " + authUrl +
                ", Token Property: " + tokenPropertyName +
                ", HTTP Method: " + savedHttpMethod +
                ", Content-Type: " + savedContentType);
    }

    // Implement HttpHandler methods - REACTIVE SESSION MANAGEMENT
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // ALWAYS log this to verify the handler is being called
        api.logging().logToOutput("[HANDLER] HTTP Request intercepted - Handler is working!");

        String host = requestToBeSent.httpService().host();
        String url = requestToBeSent.url();
        String method = requestToBeSent.method();
        
        // Extract the path from the full URL for better matching
        String path = url;
        try {
            if (url.startsWith("http://") || url.startsWith("https://")) {
                java.net.URL parsedUrl = new java.net.URL(url);
                path = parsedUrl.getPath();
                if (parsedUrl.getQuery() != null) {
                    path += "?" + parsedUrl.getQuery();
                }
            }
        } catch (Exception e) {
            // Use full URL if parsing fails
        }
        
        // Debug logging to see what's happening
        api.logging().logToOutput("[DEBUG] Full URL: " + url);
        api.logging().logToOutput("[DEBUG] Host: " + host);
        api.logging().logToOutput("[DEBUG] Path: " + path);
        api.logging().logToOutput("[DEBUG] Method: " + method);

        // Check if request is in scope
        boolean inScope = api.scope().isInScope(url);
        api.logging().logToOutput("[SCOPE] Request: " + method + " " + host + url + " - In scope: " + inScope);

        if (!inScope) {
            api.logging().logToOutput("[SCOPE] Request is out of scope - ignoring");
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        // Check if this is an authentication request
        if (isAuthenticationRequest(url)) {
            api.logging().logToOutput("[AUTH-REQUEST] Detected authentication request - skipping JWT injection and monitoring");
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Get current enabled status from checkbox (real-time)
        boolean currentlyEnabled = enabledCheckbox != null ? enabledCheckbox.isSelected() : enabled;

        api.logging().logToOutput("=== HTTP REQUEST (IN SCOPE): " + method + " " + host + url + " ===");
        api.logging().logToOutput("[REACTIVE] Extension enabled: " + currentlyEnabled);
        api.logging().logToOutput("[REACTIVE] Vault status: " + (isVaultEmpty() ? "EMPTY" : "HAS JWT"));

        // Variables for the request we'll actually send
        HttpRequestToBeSent finalRequestToBeSent = requestToBeSent;
        String injectedJWT = null;
        
        // Check if request already has a JWT
        String existingJWT = extractJWTFromRequest(requestToBeSent);
        if (existingJWT != null && !existingJWT.trim().isEmpty()) {
            api.logging().logToOutput("[REACTIVE] Request already has JWT: " + existingJWT.substring(0, Math.min(30, existingJWT.length())) + "...");
        } else {
            api.logging().logToOutput("[REACTIVE] Request has NO JWT token");
        }

        // REACTIVE APPROACH: If extension is enabled and vault is not empty, inject JWT
        if (currentlyEnabled && !isVaultEmpty()) {
            // Only inject JWT if the request already has a JWT (to replace it)
            // This ensures we only monitor JWT traffic, not all traffic
            if (existingJWT != null && !existingJWT.trim().isEmpty()) {
                String vaultJWT = getJWTFromVault();
                api.logging().logToOutput("[REACTIVE] REPLACING existing JWT with vault JWT");
                api.logging().logToOutput("[REACTIVE] JWT Header Name: " + jwtHeaderName);
                api.logging().logToOutput("[REACTIVE] JWT Prefix: '" + jwtPrefix + "'");
                api.logging().logToOutput("[REACTIVE] Full header value: " + jwtPrefix + vaultJWT);

                try {
                    // Inject JWT from vault into the request and remove caching headers
                    HttpRequest modifiedRequest = requestToBeSent
                        .withHeader(jwtHeaderName, jwtPrefix + vaultJWT)
                        .withRemovedHeader("If-None-Match")
                        .withRemovedHeader("If-Modified-Since")
                        .withRemovedHeader("If-Unmodified-Since")
                        .withRemovedHeader("If-Match")
                        .withRemovedHeader("If-Range");
                    
                    injectedJWT = vaultJWT;  // Track that we injected a JWT
                    api.logging().logToOutput("[REACTIVE] Successfully replaced JWT: " + vaultJWT.substring(0, Math.min(30, vaultJWT.length())) + "...");
                    api.logging().logToOutput("[REACTIVE] Removed caching headers to ensure fresh response");
                    
                    // Log the modified request headers to verify injection
                    api.logging().logToOutput("[REACTIVE] Modified request will have header: " + jwtHeaderName + ": " + jwtPrefix + vaultJWT.substring(0, Math.min(30, vaultJWT.length())) + "...");
                    
                    // Capture the injected request in the table BEFORE returning
                    captureRequestInTable(requestToBeSent, host, url, method, injectedJWT, "Injected JWT");
                    
                    // Return the modified request
                    return RequestToBeSentAction.continueWith(modifiedRequest);
                } catch (Exception e) {
                    api.logging().logToError("[REACTIVE] Failed to inject JWT: " + e.getMessage());
                    e.printStackTrace();
                    // Continue with original request if injection fails
                    finalRequestToBeSent = requestToBeSent;
                }
            } else {
                api.logging().logToOutput("[REACTIVE] No existing JWT to replace - vault injection skipped");
            }
        } else {
            api.logging().logToOutput("[REACTIVE] No JWT injection - Extension disabled or vault empty");
        }

        // Always capture requests that contain JWT tokens for monitoring, regardless of extension enabled state
        // This allows users to see JWT traffic flowing through the table even when disabled
        
        // Extract any existing JWT from the request for logging
        String requestJWT = extractJWTFromRequest(finalRequestToBeSent);
        
        // Check if we have a JWT to monitor (already in request - not injected)
        if (requestJWT != null && !requestJWT.trim().isEmpty()) {
            captureRequestInTable(requestToBeSent, host, url, method, requestJWT, "Bearer Token");
            
            // WORKAROUND: If the JWT is expired and extension is disabled, we know it will get 401
            // Since response handler isn't being called reliably, update status preemptively
            if (!currentlyEnabled) {
                String expirationTime = getJWTExpirationTime(requestJWT);
                if ("EXPIRED".equals(expirationTime)) {
                    api.logging().logToOutput("[WORKAROUND] JWT is expired and extension disabled - expecting 401 response");
                    // Note: The actual response update should happen in the response handler
                    // This is just logging the expected behavior
                }
            }
        } else if (injectedJWT == null) {
            // No JWT in request and we didn't inject one - don't capture
            api.logging().logToOutput("[SKIP] Request has no JWT token - not capturing in API monitor");
        }

        // Continue with the original request
        return RequestToBeSentAction.continueWith(finalRequestToBeSent);
    }
    
    // Helper method to capture requests in the table
    private void captureRequestInTable(HttpRequestToBeSent request, String host, String url, String method, String jwt, String requestType) {
        // Get current enabled status
        boolean currentlyEnabled = enabledCheckbox != null ? enabledCheckbox.isSelected() : enabled;
        
        // Determine JWT info for table
        String jwtExpirationTime = getJWTExpirationTime(jwt);
        String jwtRisk = getJWTExpirationRisk(jwtExpirationTime);
        
        api.logging().logToOutput("[CAPTURE] Request with " + requestType + " - capturing for monitoring (Extension " + (currentlyEnabled ? "enabled" : "disabled") + ")");

        // Capture variables as final for lambda
        final String finalHost = host;
        final String finalUrl = url;
        final String finalMethod = method;
        final String currentTime = dateFormat.format(new Date());
        final String finalRequestJWT = jwt;
        final String finalJwtExpirationTime = jwtExpirationTime;
        final String finalJwtRisk = jwtRisk;
        final String finalRequestType = requestType;
        final String requestData = formatHttpRequest(request); // Store original request format

        // Add to table
        final int currentRequestNumber = ++requestCounter;
        
        // Extract path from URL for better matching
        String pathForMatching = url;
        try {
            if (url.startsWith("http://") || url.startsWith("https://")) {
                java.net.URL parsedUrl = new java.net.URL(url);
                pathForMatching = parsedUrl.getPath();
                if (parsedUrl.getQuery() != null) {
                    pathForMatching += "?" + parsedUrl.getQuery();
                }
            }
        } catch (Exception e) {
            // Use full URL if parsing fails
        }
        
        // Create a unique identifier using timestamp and request counter
        String uniqueKey = host + pathForMatching + "_" + System.currentTimeMillis() + "_" + currentRequestNumber;
        
        // Update tracking maps IMMEDIATELY (not in SwingUtilities.invokeLater)
        APICallData apiCall = new APICallData(currentRequestNumber, finalHost, finalRequestType, "Pending", finalJwtRisk, currentTime, finalJwtExpirationTime);
        apiCall.setUrl(finalUrl);
        apiCall.setMethod(finalMethod);
        apiCall.setRequestData(requestData);
        apiCall.setResponseData("Response pending...");
        apiCall.setStatusCode(0);
        apiCall.setExtractedJWT(finalRequestJWT);
        apiCall.setOriginalRequest(request);
        
        // Store in maps immediately for response matching
        requestResponseMap.put(currentRequestNumber, apiCall);
        pendingRequests.put(uniqueKey, currentRequestNumber);
        
        // Store unique key in the list for this host+path (handles concurrent requests)
        java.util.List<String> keys = requestIdentifiers.computeIfAbsent(host + pathForMatching, k -> new java.util.concurrent.CopyOnWriteArrayList<>());
        keys.add(uniqueKey);
        
        api.logging().logToOutput("[CAPTURE] Stored request with key: " + host + pathForMatching + " (" + keys.size() + " pending request(s) for this endpoint)");
        
        // Now update the UI
        SwingUtilities.invokeLater(() -> {
            apiCallTableModel.addAPICall(apiCall);
            api.logging().logToOutput("[TABLE] Added request #" + currentRequestNumber + " - " + finalHost + " (" + finalRequestType + ", expires: " + finalJwtExpirationTime + ")");
        });
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // ALWAYS log this to verify the response handler is being called
        api.logging().logToOutput("[RESPONSE-HANDLER] HTTP Response intercepted - Handler is working!");
        
        String host = responseReceived.initiatingRequest().httpService().host();
        String url = responseReceived.initiatingRequest().url();
        int statusCode = responseReceived.statusCode();
        
        // Extract path from URL for matching with request
        String path = url;
        try {
            if (url.startsWith("http://") || url.startsWith("https://")) {
                java.net.URL parsedUrl = new java.net.URL(url);
                path = parsedUrl.getPath();
                if (parsedUrl.getQuery() != null) {
                    path += "?" + parsedUrl.getQuery();
                }
            }
        } catch (Exception e) {
            // Use full URL if parsing fails
        }
        
        api.logging().logToOutput("[RESPONSE-HANDLER] Response for: " + host + path + " - Status: " + statusCode);

        // Check if request was in scope
        boolean inScope = api.scope().isInScope(url);
        if (!inScope) {
            api.logging().logToOutput("[SCOPE] Response is out of scope - ignoring");
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        // Check if this is an authentication response
        if (isAuthenticationRequest(url)) {
            api.logging().logToOutput("[AUTH-RESPONSE] Detected authentication response - skipping monitoring");
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Get current enabled status from checkbox (real-time)
        boolean currentlyEnabled = enabledCheckbox != null ? enabledCheckbox.isSelected() : enabled;

        api.logging().logToOutput("=== HTTP RESPONSE (IN SCOPE) ===");
        api.logging().logToOutput("Host: " + host);
        api.logging().logToOutput("Status Code: " + statusCode);
        api.logging().logToOutput("Extension Enabled: " + currentlyEnabled);
        
        // Debug: Log response body preview
        String responseBody = responseReceived.bodyToString();
        if (responseBody != null && !responseBody.isEmpty()) {
            api.logging().logToOutput("[RESPONSE-HANDLER] Response body preview: " + 
                responseBody.substring(0, Math.min(100, responseBody.length())) + 
                (responseBody.length() > 100 ? "..." : ""));
        } else {
            api.logging().logToOutput("[RESPONSE-HANDLER] Response body is empty");
        }

        String responseData = formatHttpResponse(responseReceived);

        // Update the corresponding request with response data
        updateRequestWithResponse(host + path, responseData, statusCode, "Response received");

        // REACTIVE APPROACH: Handle 401 responses by triggering re-authentication
        if (statusCode == 401 && currentlyEnabled) {
            api.logging().logToOutput("[401-REACTIVE] Detected 401 Unauthorized response - triggering re-authentication");

            // Trigger re-authentication synchronously to ensure vault is updated before next request
            triggerReAuthentication();
        } else if (statusCode == 401) {
            api.logging().logToOutput("[401] Detected 401 Unauthorized response but extension is disabled - no re-authentication");
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    // Helper method to convert JSON body to query parameters for GET requests
    private String convertBodyToQueryParams(String jsonBody) {
        try {
            if (jsonBody == null || jsonBody.trim().isEmpty()) {
                return "";
            }
            
            // Simple JSON parsing - handles basic {"key":"value"} format
            // Remove curly braces and whitespace
            String cleanedBody = jsonBody.trim();
            if (cleanedBody.startsWith("{") && cleanedBody.endsWith("}")) {
                cleanedBody = cleanedBody.substring(1, cleanedBody.length() - 1);
            }
            
            // Split by comma to get key-value pairs
            String[] pairs = cleanedBody.split(",");
            StringBuilder queryParams = new StringBuilder();
            
            for (String pair : pairs) {
                // Split by colon to separate key and value
                String[] keyValue = pair.split(":", 2);
                if (keyValue.length == 2) {
                    // Clean up the key and value
                    String key = keyValue[0].trim().replaceAll("\"", "");
                    String value = keyValue[1].trim().replaceAll("\"", "");
                    
                    // URL encode the values
                    if (queryParams.length() > 0) {
                        queryParams.append("&");
                    }
                    queryParams.append(java.net.URLEncoder.encode(key, "UTF-8"));
                    queryParams.append("=");
                    queryParams.append(java.net.URLEncoder.encode(value, "UTF-8"));
                }
            }
            
            return queryParams.toString();
            
        } catch (Exception e) {
            api.logging().logToError("[CONVERT] Error converting body to query params: " + e.getMessage());
            return "";
        }
    }
    
    /**
     * Clean up resources for proper extension unloading
     */
    public void cleanup() {
        // Clear JWT vault
        jwtVault = null;
        
        // Clear API call data
        if (apiCallTableModel != null) {
            SwingUtilities.invokeLater(() -> {
                apiCallTableModel.setRowCount(0);
            });
        }
        
        // Clear any stored data
        authUrl = null;
        username = null;
        password = null;
        savedHttpMethod = null;
        savedContentType = null;
        savedRequestBody = null;
        
        api.logging().logToOutput("SessionManagement cleanup completed");
    }
}
