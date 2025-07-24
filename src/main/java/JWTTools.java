import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.EditorOptions;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JWTTools {
    private MontoyaApi api;
    private JPanel mainPanel;
    
    // UI Components
    private HttpRequestEditor requestEditor;
    private JTabbedPane requestResponseTabs;
    private JTextArea jwtTokenArea;
    private JTextArea decodedHeaderArea;
    private JTextArea decodedPayloadArea;
    private JTextArea decodedSignatureArea;
    private JTextArea securityAnalysisArea;
    private JWTSecurityAnalyzer securityAnalyzer;
    private JWTTokenEditor tokenEditor; // Reference to main token editor tab
    private JButton extractTokenButton;
    private JButton decodeTokenButton;
    private JButton sendToEditorButton;
    private JButton clearButton;
    private JLabel statusLabel;
    
    // Data
    private HttpRequestResponse currentRequestResponse;
    private String extractedJWT;
    
    public JWTTools(MontoyaApi api) {
        this.api = api;
        this.securityAnalyzer = new JWTSecurityAnalyzer(api);
        // Token editor will be set via setTokenEditor() method
        initializeUI();
    }
    
    public JPanel getUI() {
        return mainPanel;
    }
    
    /**
     * Set the reference to the main Token Editor tab
     */
    public void setTokenEditor(JWTTokenEditor tokenEditor) {
        this.tokenEditor = tokenEditor;
        // Enable the send to editor button if it exists
        if (sendToEditorButton != null) {
            sendToEditorButton.setEnabled(true);
        }
    }
    
    /**
     * Public method to extract JWT tokens from text - used by other components like AttackTools
     * @param text Text to search for JWT tokens
     * @param source Source description (e.g., "REQUEST", "RESPONSE")
     * @return List of found JWT tokens
     */
    public static List<String> extractJWTFromText(String text, String source) {
        List<String> tokens = new ArrayList<>();
        
        // First, look for JWT patterns (tokens starting with eyJ)
        Pattern jwtPattern = Pattern.compile("(eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*)");
        Matcher jwtMatcher = jwtPattern.matcher(text);
        while (jwtMatcher.find()) {
            String token = jwtMatcher.group(1);
            if (isValidJWTStructureStatic(token)) {
                tokens.add(token);
            }
        }
        
        // If no JWTs found, look for Bearer tokens (Authorization: Bearer <token>)
        if (tokens.isEmpty()) {
            Pattern bearerPattern = Pattern.compile("(?i)Authorization:\\s*Bearer\\s+([A-Za-z0-9+/=._-]+)");
            Matcher bearerMatcher = bearerPattern.matcher(text);
            while (bearerMatcher.find()) {
                String token = bearerMatcher.group(1).trim();
                if (token.length() > 10) { // Basic validation for token length
                    tokens.add(token);
                }
            }
        }
        
        return tokens;
    }
    
    /**
     * Static version of JWT structure validation for use by static method
     */
    private static boolean isValidJWTStructureStatic(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }
            
            // Try to decode header to verify it's valid JWT
            String header = decodeBase64URLStatic(parts[0]);
            if (header.contains("\"alg\"") || header.contains("\"typ\"")) {
                return true;
            }
            
            return false;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Static version of Base64 URL decoding for use by static methods
     */
    private static String decodeBase64URLStatic(String encoded) throws Exception {
        String padded = addPaddingStatic(encoded);
        byte[] decoded = Base64.getUrlDecoder().decode(padded);
        return new String(decoded, "UTF-8");
    }
    
    /**
     * Static version of padding addition for use by static methods
     */
    private static String addPaddingStatic(String base64) {
        while (base64.length() % 4 != 0) {
            base64 += "=";
        }
        return base64;
    }
    
    /**
     * Process a request sent from proxy context menu
     */
    public void processRequest(HttpRequestResponse requestResponse) {
        SwingUtilities.invokeLater(() -> {
            try {
                api.logging().logToOutput("JWT Tools: processRequest called");
                
                this.currentRequestResponse = requestResponse;
                
                // Debug: Check what we received
                if (requestResponse != null) {
                    api.logging().logToOutput("JWT Tools: RequestResponse object is not null");
                    
                    if (requestResponse.request() != null) {
                        api.logging().logToOutput("JWT Tools: Request is not null, length: " + requestResponse.request().toString().length());
                        api.logging().logToOutput("JWT Tools: Request preview: " + requestResponse.request().toString().substring(0, Math.min(100, requestResponse.request().toString().length())));
                    } else {
                        api.logging().logToOutput("JWT Tools: Request is null!");
                    }
                    
                    if (requestResponse.response() != null) {
                        api.logging().logToOutput("JWT Tools: Response is not null, length: " + requestResponse.response().toString().length());
                    } else {
                        api.logging().logToOutput("JWT Tools: Response is null (may be normal for some requests)");
                    }
                } else {
                    api.logging().logToOutput("JWT Tools: RequestResponse object is null!");
                }
                
                // Update the native editors
                updateNativeEditors();
                
                // Clear previous JWT analysis
                clearJWTAnalysis();
                
                // Update status
                statusLabel.setText("Request loaded. Click 'Extract Token' to find JWT or Bearer tokens.");
                
                // Auto-extract JWT tokens
                extractJWTToken();
                
                api.logging().logToOutput("JWT Tools: Request processed and displayed with native editors");
                
            } catch (Exception e) {
                api.logging().logToError("Error processing request in JWT Tools: " + e.getMessage());
                e.printStackTrace();
                statusLabel.setText("Error processing request: " + e.getMessage());
            }
        });
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Initialize native editors FIRST, before creating UI
        initializeNativeEditors();
        
        // Create main split pane
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setResizeWeight(0.4);
        
        // Top panel: Request/Response viewer with option toggle
        JPanel requestResponsePanel = createRequestResponsePanel();
        
        // Bottom panel: JWT Analysis
        JPanel jwtAnalysisPanel = createJWTAnalysisPanel();
        
        mainSplitPane.setTopComponent(requestResponsePanel);
        mainSplitPane.setBottomComponent(jwtAnalysisPanel);
        
        // Status bar
        JPanel statusPanel = createStatusPanel();
        
        mainPanel.add(mainSplitPane, BorderLayout.CENTER);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createRequestResponsePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Request Viewer"));
        
        // Add only the native request editor (removed response editor as it's irrelevant for JWT analysis)
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(new TitledBorder("HTTP Request (Native Editor)"));
        if (requestEditor != null) {
            requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
            api.logging().logToOutput("JWT Tools: Request editor added to UI");
        } else {
            api.logging().logToOutput("JWT Tools: Warning - Request editor is null");
            requestPanel.add(new JLabel("Request editor not initialized"), BorderLayout.CENTER);
        }
        
        panel.add(requestPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createJWTAnalysisPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("JWT Analysis"));
        
        // Control panel
        JPanel controlPanel = createControlPanel();
        
        // JWT display and analysis
        JPanel analysisPanel = createAnalysisDisplayPanel();
        
        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(analysisPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        extractTokenButton = new JButton("Extract Token");
        extractTokenButton.addActionListener(this::extractJWTToken);
        
        decodeTokenButton = new JButton("Analyze Token");
        decodeTokenButton.addActionListener(this::decodeJWTToken);
        decodeTokenButton.setEnabled(false);
        
        sendToEditorButton = new JButton("Send to Token Editor");
        sendToEditorButton.addActionListener(this::sendToTokenEditor);
        sendToEditorButton.setEnabled(false);
        sendToEditorButton.setToolTipText("Send the extracted JWT token to the Token Editor tab");
        
        clearButton = new JButton("Clear Analysis");
        clearButton.addActionListener(this::clearJWTAnalysis);
        
        panel.add(extractTokenButton);
        panel.add(decodeTokenButton);
        panel.add(sendToEditorButton);
        panel.add(clearButton);
        
        return panel;
    }
    
    private JPanel createAnalysisDisplayPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Split pane for token and decoded parts
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.3);
        
        // Token display
        JPanel tokenPanel = new JPanel(new BorderLayout());
        tokenPanel.setBorder(new TitledBorder("Extracted Token"));
        
        jwtTokenArea = new JTextArea(4, 50);
        ThemeManager.styleMonospaceTextArea(jwtTokenArea);
        jwtTokenArea.setFont(ThemeManager.getMonospaceFont().deriveFont(14f));
        jwtTokenArea.setLineWrap(true);
        jwtTokenArea.setWrapStyleWord(false);
        jwtTokenArea.setTabSize(4);
        
        JScrollPane tokenScrollPane = new JScrollPane(jwtTokenArea);
        tokenPanel.add(tokenScrollPane, BorderLayout.CENTER);
        
        // Decoded parts panel
        JPanel decodedPanel = createDecodedPartsPanel();
        
        splitPane.setTopComponent(tokenPanel);
        splitPane.setBottomComponent(decodedPanel);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createDecodedPartsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Token Analysis"));
        
        // Tabbed pane for header, payload, signature, and security analysis
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Header tab
        decodedHeaderArea = new JTextArea();
        ThemeManager.styleMonospaceTextArea(decodedHeaderArea);
        decodedHeaderArea.setFont(ThemeManager.getMonospaceFont().deriveFont(14f));
        decodedHeaderArea.setEditable(false);
        decodedHeaderArea.setLineWrap(false);
        JScrollPane headerScrollPane = new JScrollPane(decodedHeaderArea);
        tabbedPane.addTab("Header", headerScrollPane);
        
        // Payload tab
        decodedPayloadArea = new JTextArea();
        ThemeManager.styleMonospaceTextArea(decodedPayloadArea);
        decodedPayloadArea.setFont(ThemeManager.getMonospaceFont().deriveFont(14f));
        decodedPayloadArea.setEditable(false);
        decodedPayloadArea.setLineWrap(false);
        JScrollPane payloadScrollPane = new JScrollPane(decodedPayloadArea);
        tabbedPane.addTab("Payload", payloadScrollPane);
        
        // Signature tab
        decodedSignatureArea = new JTextArea();
        ThemeManager.styleMonospaceTextArea(decodedSignatureArea);
        decodedSignatureArea.setFont(ThemeManager.getMonospaceFont().deriveFont(14f));
        decodedSignatureArea.setEditable(false);
        decodedSignatureArea.setLineWrap(false);
        JScrollPane signatureScrollPane = new JScrollPane(decodedSignatureArea);
        tabbedPane.addTab("Signature", signatureScrollPane);
        
        // Security Analysis tab
        JTextArea securityAnalysisArea = new JTextArea();
        ThemeManager.styleTextArea(securityAnalysisArea);
        securityAnalysisArea.setFont(ThemeManager.getDefaultFont().deriveFont(14f));
        securityAnalysisArea.setEditable(false);
        securityAnalysisArea.setLineWrap(true);
        securityAnalysisArea.setWrapStyleWord(true);
        JScrollPane securityScrollPane = new JScrollPane(securityAnalysisArea);
        tabbedPane.addTab("Security Analysis", securityScrollPane);
        
        // Store reference to security analysis area for updates
        this.securityAnalysisArea = securityAnalysisArea;
        
        panel.add(tabbedPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createStatusPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createLoweredBevelBorder());
        
        statusLabel = new JLabel("Ready. Send a request from Proxy using right-click context menu.");
        ThemeManager.styleLabel(statusLabel);
        statusLabel.setFont(ThemeManager.getDefaultFont().deriveFont(Font.PLAIN, 11f));
        
        panel.add(statusLabel);
        
        return panel;
    }
    
    private void extractJWTToken(ActionEvent event) {
        extractJWTToken();
    }
    
    private void extractJWTToken() {
        try {
            if (currentRequestResponse == null) {
                statusLabel.setText("No request to analyze. Send a request from Proxy first.");
                return;
            }
            
            List<String> foundTokens = findJWTTokens();
            
            if (foundTokens.isEmpty()) {
                statusLabel.setText("No JWT or Bearer tokens found in request or response.");
                jwtTokenArea.setText("No JWT or Bearer tokens detected.\n\nChecked locations:\n- Authorization header\n- Cookie values\n- Request body\n- Response body\n- Custom headers");
                extractedJWT = null;
                decodeTokenButton.setEnabled(false);
                return;
            }
            
            // Use the first token found
            extractedJWT = foundTokens.get(0);
            jwtTokenArea.setText(extractedJWT);
            
            // Check if it's a JWT or just a Bearer token
            if (isJWTToken(extractedJWT)) {
                statusLabel.setText("JWT token extracted successfully. Click 'Analyze Token' to decode.");
                decodeTokenButton.setEnabled(true);
                
                if (foundTokens.size() > 1) {
                    statusLabel.setText("Multiple JWT tokens found (" + foundTokens.size() + "). Showing first one.");
                }
            } else {
                statusLabel.setText("Bearer token extracted (not a JWT). Click 'Analyze Token' for info.");
                decodeTokenButton.setEnabled(true); // Still allow some analysis
                
                if (foundTokens.size() > 1) {
                    statusLabel.setText("Multiple Bearer tokens found (" + foundTokens.size() + "). Showing first one (not JWT).");
                }
            }
            
            // Enable send to editor button only if tokenEditor is available
            sendToEditorButton.setEnabled(extractedJWT != null && !extractedJWT.trim().isEmpty() && tokenEditor != null);
            
            // Auto-load token into Token Editor if available
            if (tokenEditor != null && extractedJWT != null && !extractedJWT.trim().isEmpty()) {
                tokenEditor.loadToken(extractedJWT, currentRequestResponse);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error extracting JWT token: " + e.getMessage());
            statusLabel.setText("Error extracting JWT: " + e.getMessage());
            decodeTokenButton.setEnabled(false);
        }
    }
    
    private void sendToTokenEditor(ActionEvent event) {
        try {
            if (tokenEditor == null) {
                statusLabel.setText("Token Editor not available.");
                return;
            }
            
            if (extractedJWT == null || extractedJWT.trim().isEmpty()) {
                statusLabel.setText("No JWT token to send. Extract a token first.");
                return;
            }
            
            // Send token to the Token Editor tab
            tokenEditor.loadToken(extractedJWT, currentRequestResponse);
            statusLabel.setText("JWT token sent to Token Editor tab.");
            
            api.logging().logToOutput("JWT token sent to Token Editor: " + extractedJWT.substring(0, Math.min(50, extractedJWT.length())) + "...");
            
        } catch (Exception e) {
            api.logging().logToError("Error sending token to editor: " + e.getMessage());
            statusLabel.setText("Error sending token to editor: " + e.getMessage());
        }
    }
    
    private List<String> findJWTTokens() {
        List<String> tokens = new ArrayList<>();
        
        if (currentRequestResponse.request() != null) {
            // Check request headers
            String requestString = currentRequestResponse.request().toString();
            tokens.addAll(JWTTools.extractJWTFromText(requestString, "REQUEST"));
        }
        
        if (currentRequestResponse.response() != null) {
            // Check response headers and body
            String responseString = currentRequestResponse.response().toString();
            tokens.addAll(JWTTools.extractJWTFromText(responseString, "RESPONSE"));
        }
        
        return tokens;
    }
    

    
    private boolean isValidJWTStructure(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }
            
            // Try to decode header to verify it's valid JWT
            String header = decodeBase64URL(parts[0]);
            if (header.contains("\"alg\"") || header.contains("\"typ\"")) {
                return true;
            }
            
            return false;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Check if the extracted token is a JWT (has 3 parts separated by dots)
     */
    private boolean isJWTToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        
        String[] parts = token.split("\\.");
        return parts.length == 3 && isValidJWTStructure(token);
    }
    
    private void decodeJWTToken(ActionEvent event) {
        decodeJWTToken();
    }
    
    private void decodeJWTToken() {
        try {
            if (extractedJWT == null || extractedJWT.trim().isEmpty()) {
                statusLabel.setText("No token to decode. Extract a token first.");
                return;
            }
            
            // Check if this is a JWT or just a Bearer token
            if (!isJWTToken(extractedJWT)) {
                // Handle non-JWT Bearer token
                decodedHeaderArea.setText("This is a Bearer token but not a JWT.\n\n" +
                    "Bearer tokens are opaque strings that don't have a standard structure.\n" +
                    "They cannot be decoded like JWTs.\n\n" +
                    "Token Information:\n" +
                    "• Length: " + extractedJWT.length() + " characters\n" +
                    "• Type: Opaque Bearer Token\n" +
                    "• Format: Single string (not base64url encoded parts)");
                
                decodedPayloadArea.setText("Bearer Token Content:\n\n" + extractedJWT + "\n\n" +
                    "This token cannot be decoded as it's not in JWT format.\n" +
                    "It's an opaque token that only the issuing server can validate.");
                
                decodedSignatureArea.setText("No signature available.\n\n" +
                    "Bearer tokens don't have separate signature components.\n" +
                    "The entire token is validated by the authorization server.");
                
                securityAnalysisArea.setText("Security Analysis for Bearer Token:\n\n" +
                    "• Token Type: Opaque Bearer Token\n" +
                    "• Structure: Single string (no JWT components)\n" +
                    "• Validation: Server-side only\n" +
                    "• Security: Depends on server implementation\n\n" +
                    "Recommendations:\n" +
                    "• Ensure token is transmitted over HTTPS only\n" +
                    "• Implement proper token expiration on server\n" +
                    "• Use secure storage mechanisms\n" +
                    "• Consider implementing token refresh mechanisms");
                
                statusLabel.setText("Bearer token analyzed. This is not a JWT - limited analysis available.");
                return;
            }
            
            // Standard JWT decoding logic
            String[] parts = extractedJWT.split("\\.");
            if (parts.length != 3) {
                statusLabel.setText("Invalid JWT format. Expected 3 parts, found " + parts.length);
                return;
            }
            
            // Decode header
            String decodedHeader = "";
            try {
                decodedHeader = decodeBase64URL(parts[0]);
                decodedHeaderArea.setText(formatJSON(decodedHeader));
            } catch (Exception e) {
                decodedHeaderArea.setText("Error decoding header: " + e.getMessage());
            }
            
            // Decode payload
            String decodedPayload = "";
            try {
                decodedPayload = decodeBase64URL(parts[1]);
                decodedPayloadArea.setText(formatJSON(decodedPayload));
            } catch (Exception e) {
                decodedPayloadArea.setText("Error decoding payload: " + e.getMessage());
            }
            
            // Handle signature
            try {
                String signature = parts[2];
                decodedSignatureArea.setText("Signature (Base64URL): " + signature + "\n\n" +
                    "Signature verification requires the secret key.\n" +
                    "Length: " + signature.length() + " characters\n" +
                    "Raw bytes length: " + Base64.getUrlDecoder().decode(addPadding(signature)).length);
            } catch (Exception e) {
                decodedSignatureArea.setText("Error processing signature: " + e.getMessage());
            }
            
            // Perform security analysis
            try {
                SecurityAnalysisResult analysisResult = securityAnalyzer.analyzeToken(decodedHeader, decodedPayload);
                securityAnalysisArea.setText(analysisResult.generateDetailedReport());
            } catch (Exception e) {
                securityAnalysisArea.setText("Error performing security analysis: " + e.getMessage());
                api.logging().logToError("Security analysis error: " + e.getMessage());
            }
            
            statusLabel.setText("JWT decoded successfully. Check the tabs for header, payload, signature, and security analysis.");
            
        } catch (Exception e) {
            api.logging().logToError("Error decoding token: " + e.getMessage());
            statusLabel.setText("Error decoding token: " + e.getMessage());
        }
    }
    
    private String decodeBase64URL(String encoded) throws Exception {
        String padded = addPadding(encoded);
        byte[] decoded = Base64.getUrlDecoder().decode(padded);
        return new String(decoded, "UTF-8");
    }
    
    private String addPadding(String base64) {
        while (base64.length() % 4 != 0) {
            base64 += "=";
        }
        return base64;
    }
    
    private String formatJSON(String json) {
        try {
            // Simple JSON formatting - add proper indentation
            StringBuilder formatted = new StringBuilder();
            int indentLevel = 0;
            boolean inQuotes = false;
            boolean escaped = false;
            
            for (int i = 0; i < json.length(); i++) {
                char c = json.charAt(i);
                
                if (escaped) {
                    formatted.append(c);
                    escaped = false;
                    continue;
                }
                
                if (c == '\\') {
                    formatted.append(c);
                    escaped = true;
                    continue;
                }
                
                if (c == '"') {
                    inQuotes = !inQuotes;
                    formatted.append(c);
                    continue;
                }
                
                if (inQuotes) {
                    formatted.append(c);
                    continue;
                }
                
                switch (c) {
                    case '{':
                    case '[':
                        formatted.append(c);
                        formatted.append('\n');
                        indentLevel++;
                        addIndentation(formatted, indentLevel);
                        break;
                    case '}':
                    case ']':
                        formatted.append('\n');
                        indentLevel--;
                        addIndentation(formatted, indentLevel);
                        formatted.append(c);
                        break;
                    case ',':
                        formatted.append(c);
                        formatted.append('\n');
                        addIndentation(formatted, indentLevel);
                        break;
                    case ':':
                        formatted.append(c);
                        formatted.append(' ');
                        break;
                    default:
                        formatted.append(c);
                        break;
                }
            }
            
            return formatted.toString();
        } catch (Exception e) {
            return json; // Return original if formatting fails
        }
    }
    
    private void addIndentation(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append("  ");
        }
    }
    
    private void clearJWTAnalysis(ActionEvent event) {
        clearJWTAnalysis();
    }
    
    private void clearJWTAnalysis() {
        jwtTokenArea.setText("");
        decodedHeaderArea.setText("");
        decodedPayloadArea.setText("");
        decodedSignatureArea.setText("");
        securityAnalysisArea.setText("");
        extractedJWT = null;
        decodeTokenButton.setEnabled(false);
        sendToEditorButton.setEnabled(false);
        
        statusLabel.setText("Analysis cleared.");
    }
    
    /**
     * Initialize native Burp editors for syntax highlighting
     */
    private void initializeNativeEditors() {
        try {
            // Create native HTTP request editor (response editor removed as it's not needed for JWT analysis)
            requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            
            api.logging().logToOutput("JWT Tools: Native request editor initialized successfully");
        } catch (Exception e) {
            api.logging().logToError("Error initializing native request editor: " + e.getMessage());
        }
    }
    
    /**
     * Update native request editor with current request
     */
    private void updateNativeEditors() {
        try {
            if (currentRequestResponse != null) {
                api.logging().logToOutput("JWT Tools: Updating native request editor...");
                
                if (currentRequestResponse.request() != null) {
                    api.logging().logToOutput("JWT Tools: Setting request in native editor");
                    requestEditor.setRequest(currentRequestResponse.request());
                } else {
                    api.logging().logToOutput("JWT Tools: Warning - No request data available");
                }
                
                // Force UI refresh
                SwingUtilities.invokeLater(() -> {
                    try {
                        if (requestEditor.uiComponent() != null) {
                            requestEditor.uiComponent().revalidate();
                            requestEditor.uiComponent().repaint();
                        }
                        // Also refresh the main panel
                        mainPanel.revalidate();
                        mainPanel.repaint();
                        api.logging().logToOutput("JWT Tools: UI refresh completed");
                    } catch (Exception refreshEx) {
                        api.logging().logToError("Error refreshing UI: " + refreshEx.getMessage());
                    }
                });
                
                api.logging().logToOutput("JWT Tools: Native request editor updated successfully");
            } else {
                api.logging().logToOutput("JWT Tools: Warning - No currentRequestResponse available");
            }
        } catch (Exception e) {
            api.logging().logToError("Error updating native request editor: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Format HTTP request for better readability
     */
    private String formatHttpRequest(String rawRequest) {
        try {
            StringBuilder formatted = new StringBuilder();
            String[] lines = rawRequest.split("\\r?\\n");
            
            boolean inHeaders = true;
            boolean firstLine = true;
            
            for (String line : lines) {
                if (firstLine) {
                    // Format request line (method, path, version)
                    formatted.append(line).append("\n");
                    firstLine = false;
                } else if (line.trim().isEmpty()) {
                    // Empty line separates headers from body
                    formatted.append("\n");
                    inHeaders = false;
                } else if (inHeaders) {
                    // Format headers
                    if (line.contains(":")) {
                        String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            formatted.append(parts[0].trim()).append(": ").append(parts[1].trim()).append("\n");
                        } else {
                            formatted.append(line).append("\n");
                        }
                    } else {
                        formatted.append(line).append("\n");
                    }
                } else {
                    // Body content
                    formatted.append(line).append("\n");
                }
            }
            
            return formatted.toString();
        } catch (Exception e) {
            api.logging().logToError("Error formatting HTTP request: " + e.getMessage());
            return rawRequest; // Return original if formatting fails
        }
    }
    
    /**
     * Format HTTP response for better readability
     */
    private String formatHttpResponse(String rawResponse) {
        try {
            StringBuilder formatted = new StringBuilder();
            String[] lines = rawResponse.split("\\r?\\n");
            
            boolean inHeaders = true;
            boolean firstLine = true;
            
            for (String line : lines) {
                if (firstLine) {
                    // Format status line (HTTP version, status code, reason phrase)
                    formatted.append(line).append("\n");
                    firstLine = false;
                } else if (line.trim().isEmpty()) {
                    // Empty line separates headers from body
                    formatted.append("\n");
                    inHeaders = false;
                } else if (inHeaders) {
                    // Format headers
                    if (line.contains(":")) {
                        String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            formatted.append(parts[0].trim()).append(": ").append(parts[1].trim()).append("\n");
                        } else {
                            formatted.append(line).append("\n");
                        }
                    } else {
                        formatted.append(line).append("\n");
                    }
                } else {
                    // Body content - try to format JSON if it looks like JSON
                    if (line.trim().startsWith("{") || line.trim().startsWith("[")) {
                        try {
                            String formattedJson = formatJSON(line);
                            formatted.append(formattedJson).append("\n");
                        } catch (Exception jsonEx) {
                            formatted.append(line).append("\n");
                        }
                    } else {
                        formatted.append(line).append("\n");
                    }
                }
            }
            
            return formatted.toString();
        } catch (Exception e) {
            api.logging().logToError("Error formatting HTTP response: " + e.getMessage());
            return rawResponse; // Return original if formatting fails
        }
    }
    
    /**
     * Clean up resources for proper extension unloading
     */
    public void cleanup() {
        // Clear stored data
        currentRequestResponse = null;
        extractedJWT = null;
        
        // Clear UI components
        if (jwtTokenArea != null) {
            SwingUtilities.invokeLater(() -> {
                jwtTokenArea.setText("");
            });
        }
        
        if (decodedHeaderArea != null) {
            SwingUtilities.invokeLater(() -> {
                decodedHeaderArea.setText("");
                decodedPayloadArea.setText("");
                decodedSignatureArea.setText("");
                securityAnalysisArea.setText("");
            });
        }
        
        api.logging().logToOutput("JWTTools cleanup completed");
    }
}
