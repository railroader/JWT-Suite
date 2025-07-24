import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JWT Token Editor - Interactive JWT manipulation and editing component
 * Allows users to edit JWT header and payload sections and generates modified tokens
 */
public class JWTTokenEditor {
    private MontoyaApi api;
    private JPanel mainPanel;
    
    // UI Components
    private JTextArea originalTokenArea;
    private JTextArea editableHeaderArea;
    private JTextArea editablePayloadArea;
    private JTextArea generatedTokenArea;
    private JComboBox<String> algorithmComboBox;
    private JTextArea secretKeyArea;
    private JButton loadTokenButton;
    private JButton generateTokenButton;
    private JButton copyTokenButton;
    private JButton replaceInRequestButton;
    private JButton resetButton;
    private JLabel statusLabel;
    
    // Data
    private String originalToken;
    private String originalHeader;
    private String originalPayload;
    private String originalSignature;
    private HttpRequestResponse currentRequestResponse;
    
    // Algorithm options for JWT signing
    private static final String[] ALGORITHMS = {
        "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512"
    };
    
    public JWTTokenEditor(MontoyaApi api) {
        this.api = api;
        initializeUI();
    }
    
    public JPanel getUI() {
        return mainPanel;
    }
    
    /**
     * Load JWT token from external source (like JWT Tools)
     */
    public void loadToken(String jwtToken, HttpRequestResponse requestResponse) {
        this.originalToken = jwtToken;
        this.currentRequestResponse = requestResponse;
        
        SwingUtilities.invokeLater(() -> {
            originalTokenArea.setText(jwtToken);
            parseAndDisplayToken();
            statusLabel.setText("JWT token loaded. Edit header/payload and click 'Generate Token'.");
        });
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Create main split pane
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setResizeWeight(0.3);
        
        // Top panel: Original token and controls
        JPanel topPanel = createTopPanel();
        
        // Bottom panel: Editing interface
        JPanel bottomPanel = createEditingPanel();
        
        mainSplitPane.setTopComponent(topPanel);
        mainSplitPane.setBottomComponent(bottomPanel);
        
        // Status bar
        JPanel statusPanel = createStatusPanel();
        
        mainPanel.add(mainSplitPane, BorderLayout.CENTER);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createTopPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Original JWT Token"));
        
        // Original token display
        originalTokenArea = new JTextArea(4, 50);
        ThemeManager.styleMonospaceTextArea(originalTokenArea);
        originalTokenArea.setFont(ThemeManager.getMonospaceFont().deriveFont(12f));
        originalTokenArea.setLineWrap(true);
        originalTokenArea.setWrapStyleWord(false);
        originalTokenArea.setEditable(false);
        // Remove the hard-coded background color to use theme colors
        // originalTokenArea.setBackground(new Color(248, 248, 248));
        
        JScrollPane tokenScrollPane = new JScrollPane(originalTokenArea);
        panel.add(tokenScrollPane, BorderLayout.CENTER);
        
        // Control buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        loadTokenButton = new JButton("Load from Clipboard");
        loadTokenButton.addActionListener(this::loadFromClipboard);
        loadTokenButton.setToolTipText("Load JWT token from system clipboard");
        
        resetButton = new JButton("Reset");
        resetButton.addActionListener(this::resetEditor);
        resetButton.setToolTipText("Clear all fields and reset the editor");
        
        buttonPanel.add(loadTokenButton);
        buttonPanel.add(resetButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createEditingPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create tabbed pane for different editing sections
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Header editing tab
        JPanel headerPanel = createHeaderEditingPanel();
        tabbedPane.addTab("Header", headerPanel);
        
        // Payload editing tab
        JPanel payloadPanel = createPayloadEditingPanel();
        tabbedPane.addTab("Payload", payloadPanel);
        
        // Token generation tab
        JPanel generationPanel = createTokenGenerationPanel();
        tabbedPane.addTab("Generate", generationPanel);
        
        panel.add(tabbedPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createHeaderEditingPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("JWT Header Editing"));
        
        // Header editing area
        editableHeaderArea = new JTextArea(10, 50);
        ThemeManager.styleMonospaceTextArea(editableHeaderArea);
        editableHeaderArea.setFont(ThemeManager.getMonospaceFont().deriveFont(14f));
        editableHeaderArea.setLineWrap(false);
        editableHeaderArea.setTabSize(2);
        
        JScrollPane headerScrollPane = new JScrollPane(editableHeaderArea);
        panel.add(headerScrollPane, BorderLayout.CENTER);
        
        // Algorithm selection panel
        JPanel algorithmPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        algorithmPanel.add(new JLabel("Algorithm:"));
        
        algorithmComboBox = new JComboBox<>(ALGORITHMS);
        algorithmComboBox.addActionListener(this::updateAlgorithmInHeader);
        algorithmComboBox.setToolTipText("Select the JWT signing algorithm");
        algorithmPanel.add(algorithmComboBox);
        
        JButton formatHeaderButton = new JButton("Format JSON");
        formatHeaderButton.addActionListener(this::formatHeaderJSON);
        formatHeaderButton.setToolTipText("Format the header JSON for better readability");
        algorithmPanel.add(formatHeaderButton);
        
        panel.add(algorithmPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createPayloadEditingPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("JWT Payload Editing"));
        
        // Payload editing area
        editablePayloadArea = new JTextArea(15, 50);
        ThemeManager.styleMonospaceTextArea(editablePayloadArea);
        editablePayloadArea.setFont(ThemeManager.getMonospaceFont().deriveFont(14f));
        editablePayloadArea.setLineWrap(false);
        editablePayloadArea.setTabSize(2);
        
        JScrollPane payloadScrollPane = new JScrollPane(editablePayloadArea);
        panel.add(payloadScrollPane, BorderLayout.CENTER);
        
        // Payload manipulation buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton formatPayloadButton = new JButton("Format JSON");
        formatPayloadButton.addActionListener(this::formatPayloadJSON);
        formatPayloadButton.setToolTipText("Format the payload JSON for better readability");
        buttonPanel.add(formatPayloadButton);
        
        JButton addClaimButton = new JButton("Add Common Claims");
        addClaimButton.addActionListener(this::showAddClaimDialog);
        addClaimButton.setToolTipText("Add common JWT claims like exp, iat, nbf, etc.");
        buttonPanel.add(addClaimButton);
        
        JButton extendExpiryButton = new JButton("Extend Expiry");
        extendExpiryButton.addActionListener(this::extendTokenExpiry);
        extendExpiryButton.setToolTipText("Extend token expiration time by 1 hour");
        buttonPanel.add(extendExpiryButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createTokenGenerationPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Token Generation"));
        
        // Split into signing options and generated token
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.4);
        
        // Signing options panel
        JPanel signingPanel = createSigningOptionsPanel();
        
        // Generated token panel
        JPanel tokenPanel = createGeneratedTokenPanel();
        
        splitPane.setTopComponent(signingPanel);
        splitPane.setBottomComponent(tokenPanel);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createSigningOptionsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Signing Options"));
        
        JPanel optionsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Secret key input
        gbc.gridx = 0; gbc.gridy = 0;
        optionsPanel.add(new JLabel("Secret Key:"), gbc);
        
        secretKeyArea = new JTextArea(3, 30);
        ThemeManager.styleMonospaceTextArea(secretKeyArea);
        secretKeyArea.setFont(ThemeManager.getMonospaceFont().deriveFont(12f));
        secretKeyArea.setText("your-256-bit-secret");
        secretKeyArea.setToolTipText("Enter the secret key for HMAC algorithms (not used for 'none' algorithm)");
        
        gbc.gridx = 1; gbc.gridy = 0; gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 1.0;
        optionsPanel.add(new JScrollPane(secretKeyArea), gbc);
        
        // Info label
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weighty = 0;
        JLabel infoLabel = new JLabel("<html><i>Note: 'none' algorithm creates unsigned tokens. For production use, provide proper secret keys.</i></html>");
        infoLabel.setFont(infoLabel.getFont().deriveFont(Font.ITALIC, 11f));
        optionsPanel.add(infoLabel, gbc);
        
        panel.add(optionsPanel, BorderLayout.CENTER);
        
        // Generate button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        generateTokenButton = new JButton("Generate JWT Token");
        generateTokenButton.addActionListener(this::generateJWTToken);
        generateTokenButton.setFont(generateTokenButton.getFont().deriveFont(Font.BOLD));
        generateTokenButton.setToolTipText("Generate a new JWT token based on the edited header and payload");
        buttonPanel.add(generateTokenButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createGeneratedTokenPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Generated JWT Token"));
        
        // Generated token display
        generatedTokenArea = new JTextArea(4, 50);
        ThemeManager.styleMonospaceTextArea(generatedTokenArea);
        generatedTokenArea.setFont(ThemeManager.getMonospaceFont().deriveFont(12f));
        generatedTokenArea.setLineWrap(true);
        generatedTokenArea.setWrapStyleWord(false);
        generatedTokenArea.setEditable(false);
        // Remove the hard-coded background color to use theme colors
        // generatedTokenArea.setBackground(new Color(240, 255, 240)); // Light green background
        
        JScrollPane generatedScrollPane = new JScrollPane(generatedTokenArea);
        panel.add(generatedScrollPane, BorderLayout.CENTER);
        
        // Action buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        copyTokenButton = new JButton("Copy to Clipboard");
        copyTokenButton.addActionListener(this::copyToClipboard);
        copyTokenButton.setEnabled(false);
        copyTokenButton.setToolTipText("Copy the generated token to system clipboard");
        buttonPanel.add(copyTokenButton);
        
        replaceInRequestButton = new JButton("Replace in Request");
        replaceInRequestButton.addActionListener(this::replaceInRequest);
        replaceInRequestButton.setEnabled(false);
        replaceInRequestButton.setToolTipText("Replace the JWT token in the original request");
        buttonPanel.add(replaceInRequestButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createStatusPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createLoweredBevelBorder());
        
        statusLabel = new JLabel("Ready. Load a JWT token or paste one from clipboard to start editing.");
        ThemeManager.styleLabel(statusLabel);
        statusLabel.setFont(ThemeManager.getDefaultFont().deriveFont(Font.PLAIN, 11f));
        
        panel.add(statusLabel);
        
        return panel;
    }
    
    // Event handlers
    
    private void loadFromClipboard(ActionEvent event) {
        try {
            String clipboardText = (String) Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .getData(java.awt.datatransfer.DataFlavor.stringFlavor);
            
            if (clipboardText != null && !clipboardText.trim().isEmpty()) {
                // Clean up the clipboard text (remove whitespace, newlines)
                String token = clipboardText.trim().replaceAll("\\s+", "");
                
                // Basic JWT validation
                if (isValidJWTFormat(token)) {
                    originalToken = token;
                    originalTokenArea.setText(token);
                    parseAndDisplayToken();
                    statusLabel.setText("JWT token loaded from clipboard. Ready for editing.");
                } else {
                    statusLabel.setText("Invalid JWT format in clipboard. Expected format: header.payload.signature");
                    JOptionPane.showMessageDialog(mainPanel, 
                        "The clipboard content doesn't appear to be a valid JWT token.\n" +
                        "Expected format: header.payload.signature\n\n" +
                        "Found: " + (token.length() > 50 ? token.substring(0, 50) + "..." : token),
                        "Invalid JWT Format", JOptionPane.WARNING_MESSAGE);
                }
            } else {
                statusLabel.setText("Clipboard is empty or contains no text.");
            }
        } catch (Exception e) {
            api.logging().logToError("Error reading from clipboard: " + e.getMessage());
            statusLabel.setText("Error reading from clipboard: " + e.getMessage());
        }
    }
    
    private void resetEditor(ActionEvent event) {
        originalToken = null;
        originalHeader = null;
        originalPayload = null;
        originalSignature = null;
        currentRequestResponse = null;
        
        originalTokenArea.setText("");
        editableHeaderArea.setText("");
        editablePayloadArea.setText("");
        generatedTokenArea.setText("");
        secretKeyArea.setText("your-256-bit-secret");
        algorithmComboBox.setSelectedIndex(0); // Set to "none"
        
        copyTokenButton.setEnabled(false);
        replaceInRequestButton.setEnabled(false);
        
        statusLabel.setText("Editor reset. Load a JWT token to start editing.");
    }
    
    private void parseAndDisplayToken() {
        try {
            if (originalToken == null || originalToken.trim().isEmpty()) {
                statusLabel.setText("No token to parse.");
                return;
            }
            
            String[] parts = originalToken.split("\\.");
            if (parts.length != 3) {
                statusLabel.setText("Invalid JWT format. Expected 3 parts, found " + parts.length);
                return;
            }
            
            // Decode and store original parts
            originalHeader = decodeBase64URL(parts[0]);
            originalPayload = decodeBase64URL(parts[1]);
            originalSignature = parts[2];
            
            // Display in editable areas
            editableHeaderArea.setText(formatJSON(originalHeader));
            editablePayloadArea.setText(formatJSON(originalPayload));
            
            // Update algorithm combo box based on header
            updateAlgorithmComboFromHeader();
            
            statusLabel.setText("JWT token parsed successfully. Header and payload are ready for editing.");
            
        } catch (Exception e) {
            api.logging().logToError("Error parsing JWT token: " + e.getMessage());
            statusLabel.setText("Error parsing JWT: " + e.getMessage());
        }
    }
    
    private void updateAlgorithmComboFromHeader() {
        try {
            // Try to extract algorithm from header JSON
            String headerText = editableHeaderArea.getText();
            Pattern algPattern = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");
            Matcher matcher = algPattern.matcher(headerText);
            
            if (matcher.find()) {
                String algorithm = matcher.group(1);
                for (int i = 0; i < ALGORITHMS.length; i++) {
                    if (ALGORITHMS[i].equals(algorithm)) {
                        algorithmComboBox.setSelectedIndex(i);
                        break;
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error updating algorithm combo: " + e.getMessage());
        }
    }
    
    private void updateAlgorithmInHeader(ActionEvent event) {
        try {
            String selectedAlg = (String) algorithmComboBox.getSelectedItem();
            String headerText = editableHeaderArea.getText();
            
            // Update the algorithm in the header JSON
            String updatedHeader = headerText.replaceAll(
                "\"alg\"\\s*:\\s*\"[^\"]*\"",
                "\"alg\": \"" + selectedAlg + "\""
            );
            
            editableHeaderArea.setText(updatedHeader);
            statusLabel.setText("Algorithm updated to " + selectedAlg + " in header.");
            
        } catch (Exception e) {
            api.logging().logToError("Error updating algorithm in header: " + e.getMessage());
            statusLabel.setText("Error updating algorithm: " + e.getMessage());
        }
    }
    
    private void formatHeaderJSON(ActionEvent event) {
        try {
            String headerText = editableHeaderArea.getText();
            String formatted = formatJSON(headerText);
            editableHeaderArea.setText(formatted);
            statusLabel.setText("Header JSON formatted.");
        } catch (Exception e) {
            statusLabel.setText("Error formatting header JSON: " + e.getMessage());
        }
    }
    
    private void formatPayloadJSON(ActionEvent event) {
        try {
            String payloadText = editablePayloadArea.getText();
            String formatted = formatJSON(payloadText);
            editablePayloadArea.setText(formatted);
            statusLabel.setText("Payload JSON formatted.");
        } catch (Exception e) {
            statusLabel.setText("Error formatting payload JSON: " + e.getMessage());
        }
    }
    
    private void showAddClaimDialog(ActionEvent event) {
        JDialog dialog = new JDialog((JFrame) SwingUtilities.getWindowAncestor(mainPanel), 
            "Add Common JWT Claims", true);
        dialog.setLayout(new BorderLayout());
        
        JPanel claimsPanel = new JPanel(new GridLayout(0, 2, 5, 5));
        claimsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Common claims with checkboxes
        Map<String, JCheckBox> claimCheckboxes = new HashMap<>();
        
        String[] commonClaims = {
            "iss (Issuer)", "sub (Subject)", "aud (Audience)", 
            "exp (Expiration)", "iat (Issued At)", "nbf (Not Before)",
            "jti (JWT ID)", "scope", "role", "email"
        };
        
        for (String claim : commonClaims) {
            JCheckBox checkbox = new JCheckBox(claim);
            claimsPanel.add(checkbox);
            
            String key = claim.split(" ")[0]; // Extract the key part
            claimCheckboxes.put(key, checkbox);
            
            // Add a placeholder value field next to each checkbox
            JTextField valueField = new JTextField();
            valueField.setToolTipText("Value for " + claim);
            claimsPanel.add(valueField);
            
            // Store the value field reference
            checkbox.putClientProperty("valueField", valueField);
            
            // Set default values for some claims
            if (key.equals("exp")) {
                valueField.setText(String.valueOf(System.currentTimeMillis() / 1000 + 3600)); // 1 hour from now
            } else if (key.equals("iat")) {
                valueField.setText(String.valueOf(System.currentTimeMillis() / 1000)); // Now
            } else if (key.equals("iss")) {
                valueField.setText("jwt-editor");
            }
        }
        
        dialog.add(claimsPanel, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton addButton = new JButton("Add Claims");
        JButton cancelButton = new JButton("Cancel");
        
        addButton.addActionListener(e -> {
            addSelectedClaims(claimCheckboxes);
            dialog.dispose();
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(addButton);
        buttonPanel.add(cancelButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.pack();
        dialog.setLocationRelativeTo(mainPanel);
        dialog.setVisible(true);
    }
    
    private void addSelectedClaims(Map<String, JCheckBox> claimCheckboxes) {
        try {
            String payloadText = editablePayloadArea.getText();
            
            // Parse existing payload to add claims
            StringBuilder newClaims = new StringBuilder();
            
            for (Map.Entry<String, JCheckBox> entry : claimCheckboxes.entrySet()) {
                JCheckBox checkbox = entry.getValue();
                if (checkbox.isSelected()) {
                    String key = entry.getKey();
                    JTextField valueField = (JTextField) checkbox.getClientProperty("valueField");
                    String value = valueField.getText();
                    
                    if (!value.trim().isEmpty()) {
                        // Determine if value should be quoted (string) or not (number/boolean)
                        String formattedValue;
                        if (key.equals("exp") || key.equals("iat") || key.equals("nbf")) {
                            // Numeric timestamp
                            formattedValue = value;
                        } else if (value.equals("true") || value.equals("false")) {
                            // Boolean
                            formattedValue = value;
                        } else {
                            // String value
                            formattedValue = "\"" + value + "\"";
                        }
                        
                        if (newClaims.length() > 0) {
                            newClaims.append(",\n  ");
                        }
                        newClaims.append("\"").append(key).append("\": ").append(formattedValue);
                    }
                }
            }
            
            if (newClaims.length() > 0) {
                // Add claims to existing payload
                String updatedPayload;
                if (payloadText.trim().isEmpty()) {
                    updatedPayload = "{\n  " + newClaims.toString() + "\n}";
                } else {
                    // Insert before the closing brace
                    int lastBrace = payloadText.lastIndexOf("}");
                    if (lastBrace > 0) {
                        String beforeBrace = payloadText.substring(0, lastBrace).trim();
                        if (beforeBrace.endsWith("{")) {
                            // Empty payload
                            updatedPayload = beforeBrace + "\n  " + newClaims.toString() + "\n}";
                        } else {
                            // Has existing claims
                            updatedPayload = beforeBrace + ",\n  " + newClaims.toString() + "\n}";
                        }
                    } else {
                        // Malformed JSON, replace entirely
                        updatedPayload = "{\n  " + newClaims.toString() + "\n}";
                    }
                }
                
                editablePayloadArea.setText(formatJSON(updatedPayload));
                statusLabel.setText("Claims added to payload successfully.");
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error adding claims: " + e.getMessage());
            statusLabel.setText("Error adding claims: " + e.getMessage());
        }
    }
    
    private void extendTokenExpiry(ActionEvent event) {
        try {
            String payloadText = editablePayloadArea.getText();
            
            // Calculate new expiry time (current time + 1 hour)
            long newExpiry = System.currentTimeMillis() / 1000 + 3600;
            
            // Update or add exp claim
            String updatedPayload;
            if (payloadText.contains("\"exp\"")) {
                // Replace existing exp claim
                updatedPayload = payloadText.replaceAll(
                    "\"exp\"\\s*:\\s*\\d+",
                    "\"exp\": " + newExpiry
                );
            } else {
                // Add new exp claim
                int lastBrace = payloadText.lastIndexOf("}");
                if (lastBrace > 0) {
                    String beforeBrace = payloadText.substring(0, lastBrace).trim();
                    if (beforeBrace.endsWith("{")) {
                        // Empty payload
                        updatedPayload = beforeBrace + "\n  \"exp\": " + newExpiry + "\n}";
                    } else {
                        // Has existing claims
                        updatedPayload = beforeBrace + ",\n  \"exp\": " + newExpiry + "\n}";
                    }
                } else {
                    // Malformed JSON, create new
                    updatedPayload = "{\n  \"exp\": " + newExpiry + "\n}";
                }
            }
            
            editablePayloadArea.setText(formatJSON(updatedPayload));
            statusLabel.setText("Token expiry extended by 1 hour (exp: " + newExpiry + ").");
            
        } catch (Exception e) {
            api.logging().logToError("Error extending expiry: " + e.getMessage());
            statusLabel.setText("Error extending expiry: " + e.getMessage());
        }
    }
    
    private void generateJWTToken(ActionEvent event) {
        try {
            String headerText = editableHeaderArea.getText().trim();
            String payloadText = editablePayloadArea.getText().trim();
            
            if (headerText.isEmpty() || payloadText.isEmpty()) {
                statusLabel.setText("Header and payload cannot be empty.");
                return;
            }
            
            // Validate JSON format
            if (!isValidJSON(headerText) || !isValidJSON(payloadText)) {
                statusLabel.setText("Invalid JSON format in header or payload.");
                return;
            }
            
            // Encode header and payload
            String encodedHeader = encodeBase64URL(headerText);
            String encodedPayload = encodeBase64URL(payloadText);
            
            // Generate signature based on selected algorithm
            String algorithm = (String) algorithmComboBox.getSelectedItem();
            String signature;
            
            if ("none".equals(algorithm)) {
                signature = "";
            } else {
                // For this implementation, we'll create a placeholder signature
                // In a real implementation, you would use proper cryptographic signing
                String secretKey = secretKeyArea.getText().trim();
                signature = generateSignature(encodedHeader + "." + encodedPayload, algorithm, secretKey);
            }
            
            // Build the final JWT
            String generatedToken = encodedHeader + "." + encodedPayload + "." + signature;
            generatedTokenArea.setText(generatedToken);
            
            // Enable action buttons
            copyTokenButton.setEnabled(true);
            replaceInRequestButton.setEnabled(currentRequestResponse != null);
            
            statusLabel.setText("JWT token generated successfully with " + algorithm + " algorithm.");
            
        } catch (Exception e) {
            api.logging().logToError("Error generating JWT token: " + e.getMessage());
            statusLabel.setText("Error generating token: " + e.getMessage());
        }
    }
    
    private void copyToClipboard(ActionEvent event) {
        try {
            String generatedToken = generatedTokenArea.getText();
            if (generatedToken.isEmpty()) {
                statusLabel.setText("No token to copy. Generate a token first.");
                return;
            }
            
            Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(generatedToken), null);
            
            statusLabel.setText("Token copied to clipboard successfully.");
            
        } catch (Exception e) {
            api.logging().logToError("Error copying to clipboard: " + e.getMessage());
            statusLabel.setText("Error copying to clipboard: " + e.getMessage());
        }
    }
    
    private void replaceInRequest(ActionEvent event) {
        try {
            if (currentRequestResponse == null) {
                statusLabel.setText("No request available to modify.");
                return;
            }
            
            String generatedToken = generatedTokenArea.getText();
            if (generatedToken.isEmpty()) {
                statusLabel.setText("No generated token to replace. Generate a token first.");
                return;
            }
            
            // Create a modified request with the new JWT token
            HttpRequest originalRequest = currentRequestResponse.request();
            String requestString = originalRequest.toString();
            
            // Find and replace JWT tokens in the request
            String modifiedRequest = replaceJWTInRequest(requestString, generatedToken);
            
            if (!modifiedRequest.equals(requestString)) {
                // Send the modified request to Repeater
                HttpRequest newRequest = HttpRequest.httpRequest(modifiedRequest);
                api.repeater().sendToRepeater(newRequest);
                
                statusLabel.setText("Modified request sent to Repeater with new JWT token.");
            } else {
                statusLabel.setText("No JWT token found in original request to replace.");
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error replacing token in request: " + e.getMessage());
            statusLabel.setText("Error replacing token: " + e.getMessage());
        }
    }
    
    // Utility methods
    
    private boolean isValidJWTFormat(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        
        String[] parts = token.split("\\.");
        return parts.length == 3;
    }
    
    private boolean isValidJSON(String json) {
        try {
            // Simple JSON validation - check for balanced braces
            json = json.trim();
            if (!json.startsWith("{") || !json.endsWith("}")) {
                return false;
            }
            
            int braceCount = 0;
            boolean inString = false;
            boolean escaped = false;
            
            for (char c : json.toCharArray()) {
                if (escaped) {
                    escaped = false;
                    continue;
                }
                
                if (c == '\\') {
                    escaped = true;
                    continue;
                }
                
                if (c == '"') {
                    inString = !inString;
                    continue;
                }
                
                if (!inString) {
                    if (c == '{') braceCount++;
                    else if (c == '}') braceCount--;
                }
            }
            
            return braceCount == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    private String decodeBase64URL(String encoded) throws Exception {
        String padded = addPadding(encoded);
        byte[] decoded = Base64.getUrlDecoder().decode(padded);
        return new String(decoded, "UTF-8");
    }
    
    private String encodeBase64URL(String data) throws Exception {
        byte[] encoded = Base64.getUrlEncoder().withoutPadding().encode(data.getBytes("UTF-8"));
        return new String(encoded, "UTF-8");
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
    
    private String generateSignature(String data, String algorithm, String secretKey) {
        // Placeholder signature generation
        // In a real implementation, you would use proper HMAC or RSA signing
        try {
            if (secretKey.isEmpty()) {
                secretKey = "default-secret";
            }
            
            // Create a simple hash-based signature for demonstration
            int hash = (data + secretKey + algorithm).hashCode();
            String signature = Integer.toHexString(Math.abs(hash));
            
            // Pad to ensure consistent length and encode as base64url
            while (signature.length() < 8) {
                signature = "0" + signature;
            }
            
            return encodeBase64URL(signature);
        } catch (Exception e) {
            api.logging().logToError("Error generating signature: " + e.getMessage());
            return "placeholder_signature";
        }
    }
    
    private String replaceJWTInRequest(String requestString, String newToken) {
        String modifiedRequest = requestString;
        
        // Replace Authorization: Bearer tokens
        modifiedRequest = modifiedRequest.replaceAll(
            "(Authorization:\\s*Bearer\\s+)[A-Za-z0-9+/=._-]+",
            "$1" + newToken
        );
        
        // Replace JWT tokens in cookies
        modifiedRequest = modifiedRequest.replaceAll(
            "((?:^|;)\\s*[^=]*jwt[^=]*=)([A-Za-z0-9+/=._-]+(?:\\.[A-Za-z0-9+/=._-]+){2})",
            "$1" + newToken
        );
        
        // Replace JWT tokens in request body (JSON)
        modifiedRequest = modifiedRequest.replaceAll(
            "(\"(?:token|jwt|access_token)\"\\s*:\\s*\")[A-Za-z0-9+/=._-]+(?:\\.[A-Za-z0-9+/=._-]+){2}(\")",
            "$1" + newToken + "$2"
        );
        
        return modifiedRequest;
    }
    
    /**
     * Clean up resources for proper extension unloading
     */
    public void cleanup() {
        // Clear stored data
        originalToken = null;
        originalHeader = null;
        originalPayload = null;
        originalSignature = null;
        currentRequestResponse = null;
        
        // Clear UI components
        if (originalTokenArea != null) {
            SwingUtilities.invokeLater(() -> {
                originalTokenArea.setText("");
                editableHeaderArea.setText("");
                editablePayloadArea.setText("");
                generatedTokenArea.setText("");
                secretKeyArea.setText("");
            });
        }
        
        api.logging().logToOutput("JWTTokenEditor cleanup completed");
    }
}
