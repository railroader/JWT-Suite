import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Interactive JWT Editor with real-time editing, validation, and signing capabilities
 * Inspired by professional JWT manipulation tools with enhanced UX
 */
public class InteractiveJWTEditor extends JPanel {
    private static final JWTExtensionLogger logger = JWTExtensionLogger.getLogger(InteractiveJWTEditor.class);
    private static final JWTResourceTracker resourceTracker = new JWTResourceTracker();
    
    private final MontoyaApi api;
    private final ScheduledExecutorService validationExecutor;
    private final String editorId;
    
    // UI Components
    private JTextArea rawTokenArea;
    private JTextArea headerArea;
    private JTextArea payloadArea;
    private JTextArea signatureArea;
    private JLabel statusLabel;
    private JLabel validationLabel;
    private JProgressBar validationProgress;
    private JTabbedPane mainTabs;
    private JPanel validationPanel;
    private JPanel signingPanel;
    private JTextArea signatureKeyArea;
    private JComboBox<String> algorithmCombo;
    private JButton signButton;
    private JButton validateButton;
    private JButton resetButton;
    private JCheckBox autoValidateCheckbox;
    private JCheckBox autoSignCheckbox;
    private JTextArea validationResultsArea;
    private JScrollPane headerScrollPane;
    private JScrollPane payloadScrollPane;
    private JScrollPane signatureScrollPane;
    
    // Real-time editing state
    private AdvancedJWTParser.ParsedJWTResult currentParsedJWT;
    private boolean isUpdating = false;
    private boolean hasUnsavedChanges = false;
    private String lastValidToken = "";
    private long lastValidationTime = 0;
    private CompletableFuture<Void> currentValidation;
    
    // Validation and signing configuration
    private final String[] SUPPORTED_ALGORITHMS = {
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", 
        "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "none"
    };
    
    private final Map<String, String> algorithmDescriptions = Collections.unmodifiableMap(
        new HashMap<String, String>() {{
            put("HS256", "HMAC using SHA-256 (Symmetric)");
            put("HS384", "HMAC using SHA-384 (Symmetric)");
            put("HS512", "HMAC using SHA-512 (Symmetric)");
            put("RS256", "RSA using SHA-256 (Asymmetric)");
            put("RS384", "RSA using SHA-384 (Asymmetric)");
            put("RS512", "RSA using SHA-512 (Asymmetric)");
            put("ES256", "ECDSA using P-256 and SHA-256 (Asymmetric)");
            put("ES384", "ECDSA using P-384 and SHA-384 (Asymmetric)");
            put("ES512", "ECDSA using P-521 and SHA-512 (Asymmetric)");
            put("PS256", "RSA PSS using SHA-256 (Asymmetric)");
            put("PS384", "RSA PSS using SHA-384 (Asymmetric)");
            put("PS512", "RSA PSS using SHA-512 (Asymmetric)");
            put("none", "No signature (Unsecured JWT)");
        }}
    );
    
    /**
     * Real-time validation result with UI feedback
     */
    private static class ValidationResult {
        private final boolean isValid;
        private final String statusMessage;
        private final String detailedMessage;
        private final Color statusColor;
        private final AdvancedVulnerabilityDetector.VulnerabilityAssessment assessment;
        
        public ValidationResult(boolean valid, String status, String details, Color color, 
                              AdvancedVulnerabilityDetector.VulnerabilityAssessment assessment) {
            this.isValid = valid;
            this.statusMessage = status;
            this.detailedMessage = details;
            this.statusColor = color;
            this.assessment = assessment;
        }
        
        public boolean isValid() { return isValid; }
        public String getStatusMessage() { return statusMessage; }
        public String getDetailedMessage() { return detailedMessage; }
        public Color getStatusColor() { return statusColor; }
        public AdvancedVulnerabilityDetector.VulnerabilityAssessment getAssessment() { return assessment; }
    }
    
    public InteractiveJWTEditor(MontoyaApi api) {
        this.api = api;
        this.editorId = "JWTEditor-" + UUID.randomUUID().toString();
        this.validationExecutor = Executors.newSingleThreadScheduledExecutor();
        
        resourceTracker.trackResource(editorId);
        
        initializeUI();
        setupEventHandlers();
        setupValidationScheduler();
        
        logger.debug("Interactive JWT Editor initialized: %s", editorId);
    }
    
    /**
     * Initialize the user interface with modern, responsive design
     */
    private void initializeUI() {
        setLayout(new BorderLayout());
        
        // Main content with tabs
        mainTabs = new JTabbedPane();
        ThemeManager.styleComponent(mainTabs);
        
        // Editor tab
        JPanel editorPanel = createEditorPanel();
        mainTabs.addTab("JWT Editor", editorPanel);
        
        // Validation tab
        JPanel validationTab = createValidationPanel();
        mainTabs.addTab("Security Analysis", validationTab);
        
        // Signing tab
        JPanel signingTab = createSigningPanel();
        mainTabs.addTab("Token Signing", signingTab);
        
        add(mainTabs, BorderLayout.CENTER);
        
        // Status bar
        JPanel statusBar = createStatusBar();
        add(statusBar, BorderLayout.SOUTH);
    }
    
    /**
     * Create the main JWT editor panel with split panes
     */
    private JPanel createEditorPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        ThemeManager.styleComponent(panel);
        
        // Raw token input area
        JPanel rawTokenPanel = new JPanel(new BorderLayout());
        rawTokenPanel.setBorder(BorderFactory.createTitledBorder("Raw JWT Token"));
        
        rawTokenArea = new JTextArea(4, 80);
        rawTokenArea.setLineWrap(true);
        rawTokenArea.setWrapStyleWord(true);
        rawTokenArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ThemeManager.styleTextArea(rawTokenArea);
        
        JScrollPane rawTokenScroll = new JScrollPane(rawTokenArea);
        rawTokenPanel.add(rawTokenScroll, BorderLayout.CENTER);
        
        // Control buttons
        JPanel rawTokenControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        validateButton = new JButton("Validate");
        resetButton = new JButton("Reset");
        autoValidateCheckbox = new JCheckBox("Auto-validate", true);
        
        ThemeManager.styleButton(validateButton);
        ThemeManager.styleButton(resetButton);
        ThemeManager.styleComponent(autoValidateCheckbox);
        
        rawTokenControls.add(validateButton);
        rawTokenControls.add(resetButton);
        rawTokenControls.add(autoValidateCheckbox);
        
        rawTokenPanel.add(rawTokenControls, BorderLayout.SOUTH);
        
        panel.add(rawTokenPanel, BorderLayout.NORTH);
        
        // JWT components editor (Header, Payload, Signature)
        JSplitPane componentsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        componentsSplit.setResizeWeight(0.33);
        componentsSplit.setOneTouchExpandable(true);
        
        // Header panel
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createTitledBorder("Header (Algorithm & Metadata)"));
        
        headerArea = new JTextArea();
        headerArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        headerArea.setTabSize(2);
        ThemeManager.styleTextArea(headerArea);
        
        headerScrollPane = new JScrollPane(headerArea);
        headerPanel.add(headerScrollPane, BorderLayout.CENTER);
        
        // Payload panel
        JPanel payloadPanel = new JPanel(new BorderLayout());
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Payload (Claims & Data)"));
        
        payloadArea = new JTextArea();
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        payloadArea.setTabSize(2);
        ThemeManager.styleTextArea(payloadArea);
        
        payloadScrollPane = new JScrollPane(payloadArea);
        payloadPanel.add(payloadScrollPane, BorderLayout.CENTER);
        
        // Signature panel
        JPanel signaturePanel = new JPanel(new BorderLayout());
        signaturePanel.setBorder(BorderFactory.createTitledBorder("Signature (Base64URL)"));
        
        signatureArea = new JTextArea();
        signatureArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        signatureArea.setEditable(false); // Signature is computed, not manually edited
        ThemeManager.styleTextArea(signatureArea);
        
        signatureScrollPane = new JScrollPane(signatureArea);
        signaturePanel.add(signatureScrollPane, BorderLayout.CENTER);
        
        // Add components to split pane
        JSplitPane leftSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, headerPanel, payloadPanel);
        leftSplit.setResizeWeight(0.5);
        leftSplit.setOneTouchExpandable(true);
        
        componentsSplit.setLeftComponent(leftSplit);
        componentsSplit.setRightComponent(signaturePanel);
        
        panel.add(componentsSplit, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Create the validation panel with security analysis
     */
    private JPanel createValidationPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        ThemeManager.styleComponent(panel);
        
        // Validation controls
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlsPanel.setBorder(BorderFactory.createTitledBorder("Validation Controls"));
        
        JButton runAnalysisButton = new JButton("Run Security Analysis");
        JButton exportResultsButton = new JButton("Export Results");
        
        ThemeManager.styleButton(runAnalysisButton);
        ThemeManager.styleButton(exportResultsButton);
        
        controlsPanel.add(runAnalysisButton);
        controlsPanel.add(exportResultsButton);
        
        panel.add(controlsPanel, BorderLayout.NORTH);
        
        // Validation results
        validationResultsArea = new JTextArea();
        validationResultsArea.setEditable(false);
        validationResultsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        ThemeManager.styleTextArea(validationResultsArea);
        
        JScrollPane validationScroll = new JScrollPane(validationResultsArea);
        validationScroll.setBorder(BorderFactory.createTitledBorder("Security Analysis Results"));
        
        panel.add(validationScroll, BorderLayout.CENTER);
        
        // Setup button actions
        runAnalysisButton.addActionListener(e -> runSecurityAnalysis());
        exportResultsButton.addActionListener(e -> exportAnalysisResults());
        
        return panel;
    }
    
    /**
     * Create the signing panel for JWT manipulation
     */
    private JPanel createSigningPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        ThemeManager.styleComponent(panel);
        
        // Signing configuration
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("Signing Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        
        // Algorithm selection
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
        configPanel.add(new JLabel("Algorithm:"), gbc);
        
        algorithmCombo = new JComboBox<>(SUPPORTED_ALGORITHMS);
        algorithmCombo.setSelectedItem("HS256");
        ThemeManager.styleComponent(algorithmCombo);
        
        gbc.gridx = 1; gbc.gridy = 0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        configPanel.add(algorithmCombo, gbc);
        
        // Auto-sign checkbox
        autoSignCheckbox = new JCheckBox("Auto-sign on changes", false);
        ThemeManager.styleComponent(autoSignCheckbox);
        
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2;
        configPanel.add(autoSignCheckbox, gbc);
        
        panel.add(configPanel, BorderLayout.NORTH);
        
        // Signing key input
        JPanel keyPanel = new JPanel(new BorderLayout());
        keyPanel.setBorder(BorderFactory.createTitledBorder("Signing Key (Secret/Private Key)"));
        
        signatureKeyArea = new JTextArea(8, 60);
        signatureKeyArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        signatureKeyArea.setLineWrap(true);
        signatureKeyArea.setWrapStyleWord(false);
        ThemeManager.styleTextArea(signatureKeyArea);
        
        JScrollPane keyScroll = new JScrollPane(signatureKeyArea);
        keyPanel.add(keyScroll, BorderLayout.CENTER);
        
        // Key management buttons
        JPanel keyButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        signButton = new JButton("Sign Token");
        JButton generateKeyButton = new JButton("Generate Key");
        JButton loadKeyButton = new JButton("Load Key");
        JButton clearKeyButton = new JButton("Clear");
        
        ThemeManager.styleButton(signButton);
        ThemeManager.styleButton(generateKeyButton);
        ThemeManager.styleButton(loadKeyButton);
        ThemeManager.styleButton(clearKeyButton);
        
        keyButtonsPanel.add(signButton);
        keyButtonsPanel.add(generateKeyButton);
        keyButtonsPanel.add(loadKeyButton);
        keyButtonsPanel.add(clearKeyButton);
        
        keyPanel.add(keyButtonsPanel, BorderLayout.SOUTH);
        
        panel.add(keyPanel, BorderLayout.CENTER);
        
        // Setup button actions
        signButton.addActionListener(e -> signCurrentToken());
        generateKeyButton.addActionListener(e -> generateSigningKey());
        loadKeyButton.addActionListener(e -> loadSigningKey());
        clearKeyButton.addActionListener(e -> signatureKeyArea.setText(""));
        
        return panel;
    }
    
    /**
     * Create status bar with validation indicators
     */
    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createLoweredBevelBorder());
        ThemeManager.styleComponent(statusBar);
        
        statusLabel = new JLabel("Ready");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        ThemeManager.styleComponent(statusLabel);
        
        validationLabel = new JLabel("No token loaded");
        validationLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        ThemeManager.styleComponent(validationLabel);
        
        validationProgress = new JProgressBar();
        validationProgress.setVisible(false);
        validationProgress.setPreferredSize(new Dimension(100, 16));
        ThemeManager.styleComponent(validationProgress);
        
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leftPanel.add(statusLabel);
        leftPanel.add(Box.createHorizontalStrut(20));
        leftPanel.add(validationLabel);
        
        statusBar.add(leftPanel, BorderLayout.WEST);
        statusBar.add(validationProgress, BorderLayout.EAST);
        
        return statusBar;
    }
    
    /**
     * Setup event handlers for real-time editing
     */
    private void setupEventHandlers() {
        // Raw token area handler
        rawTokenArea.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { handleRawTokenChange(); }
            public void removeUpdate(DocumentEvent e) { handleRawTokenChange(); }
            public void changedUpdate(DocumentEvent e) { handleRawTokenChange(); }
        });
        
        // Header area handler
        headerArea.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { handleComponentChange(); }
            public void removeUpdate(DocumentEvent e) { handleComponentChange(); }
            public void changedUpdate(DocumentEvent e) { handleComponentChange(); }
        });
        
        // Payload area handler
        payloadArea.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { handleComponentChange(); }
            public void removeUpdate(DocumentEvent e) { handleComponentChange(); }
            public void changedUpdate(DocumentEvent e) { handleComponentChange(); }
        });
        
        // Button handlers
        validateButton.addActionListener(e -> validateCurrentToken());
        resetButton.addActionListener(e -> resetEditor());
        
        // Algorithm combo handler
        algorithmCombo.addActionListener(e -> handleAlgorithmChange());
        
        // Auto-sign handler
        autoSignCheckbox.addActionListener(e -> {
            if (autoSignCheckbox.isSelected() && hasValidToken()) {
                scheduleAutoSign();
            }
        });
        
        // Keyboard shortcuts
        setupKeyboardShortcuts();
    }
    
    /**
     * Setup keyboard shortcuts for common operations
     */
    private void setupKeyboardShortcuts() {
        // Ctrl+Enter to validate
        KeyStroke validateShortcut = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_DOWN_MASK);
        getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(validateShortcut, "validate");
        getActionMap().put("validate", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                validateCurrentToken();
            }
        });
        
        // Ctrl+R to reset
        KeyStroke resetShortcut = KeyStroke.getKeyStroke(KeyEvent.VK_R, KeyEvent.CTRL_DOWN_MASK);
        getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(resetShortcut, "reset");
        getActionMap().put("reset", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                resetEditor();
            }
        });
        
        // Ctrl+S to sign
        KeyStroke signShortcut = KeyStroke.getKeyStroke(KeyEvent.VK_S, KeyEvent.CTRL_DOWN_MASK);
        getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(signShortcut, "sign");
        getActionMap().put("sign", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                signCurrentToken();
            }
        });
    }
    
    /**
     * Setup validation scheduler for auto-validation
     */
    private void setupValidationScheduler() {
        // Schedule validation checks every 500ms when auto-validate is enabled
        validationExecutor.scheduleWithFixedDelay(() -> {
            if (autoValidateCheckbox.isSelected() && hasUnsavedChanges && !isUpdating) {
                SwingUtilities.invokeLater(this::performBackgroundValidation);
            }
        }, 500, 500, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Handle raw token input changes
     */
    private void handleRawTokenChange() {
        if (isUpdating) return;
        
        hasUnsavedChanges = true;
        updateStatus("Token modified", ThemeManager.getWarningColor());
        
        String token = rawTokenArea.getText().trim();
        if (!token.isEmpty()) {
            parseAndUpdateComponents(token);
        } else {
            clearComponents();
        }
    }
    
    /**
     * Handle JWT component changes (header/payload)
     */
    private void handleComponentChange() {
        if (isUpdating) return;
        
        hasUnsavedChanges = true;
        updateStatus("Components modified", ThemeManager.getWarningColor());
        
        if (hasValidComponents()) {
            reconstructTokenFromComponents();
            
            if (autoSignCheckbox.isSelected()) {
                scheduleAutoSign();
            }
        }
    }
    
    /**
     * Handle algorithm selection changes
     */
    private void handleAlgorithmChange() {
        String selectedAlg = (String) algorithmCombo.getSelectedItem();
        if (selectedAlg != null) {
            updateAlgorithmInHeader(selectedAlg);
            
            // Update key area placeholder based on algorithm
            updateKeyAreaPlaceholder(selectedAlg);
        }
    }
    
    /**
     * Parse raw token and update component areas
     */
    private void parseAndUpdateComponents(String token) {
        try {
            isUpdating = true;
            
            AdvancedJWTParser.ParsedJWTResult parsedResult = AdvancedJWTParser.parseWithSecurityAnalysis(token);
            currentParsedJWT = parsedResult;
            
            // Update component text areas
            headerArea.setText(formatJson(parsedResult.getComponents().getHeaderJson()));
            payloadArea.setText(formatJson(parsedResult.getComponents().getPayloadJson()));
            signatureArea.setText(parsedResult.getComponents().getEncodedSignature());
            
            // Update algorithm combo
            String algorithm = parsedResult.getAlgorithm();
            if (algorithm != null) {
                algorithmCombo.setSelectedItem(algorithm);
            }
            
            // Update validation status
            if (parsedResult.getValidation().isValid()) {
                updateValidationStatus("Token parsed successfully", ThemeManager.getSuccessColor());
            } else {
                updateValidationStatus("Token has validation errors", ThemeManager.getErrorColor());
            }
            
            lastValidToken = token;
            hasUnsavedChanges = false;
            
        } catch (Exception e) {
            logger.warn("Failed to parse token: %s", e.getMessage());
            updateValidationStatus("Invalid token format", ThemeManager.getErrorColor());
            clearComponents();
        } finally {
            isUpdating = false;
        }
    }
    
    /**
     * Reconstruct token from components
     */
    private void reconstructTokenFromComponents() {
        try {
            isUpdating = true;
            
            String headerJson = headerArea.getText().trim();
            String payloadJson = payloadArea.getText().trim();
            
            if (headerJson.isEmpty() || payloadJson.isEmpty()) {
                return;
            }
            
            // Encode header and payload
            String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
            
            // Keep existing signature or make empty
            String signature = signatureArea.getText().trim();
            
            // Reconstruct token
            String reconstructedToken = encodedHeader + "." + encodedPayload + "." + signature;
            rawTokenArea.setText(reconstructedToken);
            
            updateStatus("Token reconstructed from components", ThemeManager.getInfoColor());
            
        } catch (Exception e) {
            logger.warn("Failed to reconstruct token: %s", e.getMessage());
            updateStatus("Error reconstructing token", ThemeManager.getErrorColor());
        } finally {
            isUpdating = false;
        }
    }
    
    /**
     * Validate current token
     */
    private void validateCurrentToken() {
        String token = rawTokenArea.getText().trim();
        if (token.isEmpty()) {
            updateValidationStatus("No token to validate", ThemeManager.getWarningColor());
            return;
        }
        
        // Show validation progress
        validationProgress.setVisible(true);
        validationProgress.setIndeterminate(true);
        updateStatus("Validating token...", ThemeManager.getInfoColor());
        
        // Perform validation in background
        CompletableFuture.supplyAsync(() -> performValidation(token))
            .thenAccept(result -> SwingUtilities.invokeLater(() -> displayValidationResult(result)));
    }
    
    /**
     * Perform background validation without UI blocking
     */
    private void performBackgroundValidation() {
        String token = rawTokenArea.getText().trim();
        if (token.isEmpty() || token.equals(lastValidToken)) {
            return;
        }
        
        // Cancel any existing validation
        if (currentValidation != null && !currentValidation.isDone()) {
            currentValidation.cancel(false);
        }
        
        currentValidation = CompletableFuture.supplyAsync(() -> performValidation(token))
            .thenAccept(result -> SwingUtilities.invokeLater(() -> {
                displayValidationResult(result);
                lastValidToken = token;
                hasUnsavedChanges = false;
            }));
    }
    
    /**
     * Perform actual validation logic
     */
    private ValidationResult performValidation(String token) {
        try {
            AdvancedJWTParser.ParsedJWTResult parsedResult = AdvancedJWTParser.parseWithSecurityAnalysis(token);
            AdvancedVulnerabilityDetector.VulnerabilityAssessment assessment = 
                AdvancedVulnerabilityDetector.assessVulnerabilities(parsedResult);
            
            boolean isValid = parsedResult.getValidation().isValid();
            String status = isValid ? "Valid JWT" : "Invalid JWT";
            Color color = isValid ? ThemeManager.getSuccessColor() : ThemeManager.getErrorColor();
            
            StringBuilder details = new StringBuilder();
            details.append("Token Structure: ").append(isValid ? "Valid" : "Invalid").append("\n");
            details.append("Algorithm: ").append(parsedResult.getAlgorithm()).append("\n");
            details.append("Risk Level: ").append(assessment.getRiskScore().getRiskLevel()).append("\n");
            details.append("Critical Vulnerabilities: ").append(assessment.getCriticalVulnerabilities().size()).append("\n");
            
            if (!parsedResult.getValidation().getErrors().isEmpty()) {
                details.append("\nValidation Errors:\n");
                for (String error : parsedResult.getValidation().getErrors()) {
                    details.append("• ").append(error).append("\n");
                }
            }
            
            return new ValidationResult(isValid, status, details.toString(), color, assessment);
            
        } catch (Exception e) {
            return new ValidationResult(false, "Validation Error", 
                "Error during validation: " + e.getMessage(), 
                ThemeManager.getErrorColor(), null);
        }
    }
    
    /**
     * Display validation result in UI
     */
    private void displayValidationResult(ValidationResult result) {
        validationProgress.setVisible(false);
        
        updateValidationStatus(result.getStatusMessage(), result.getStatusColor());
        
        // Update main validation display if on validation tab
        if (mainTabs.getSelectedIndex() == 1) { // Validation tab
            updateValidationResultsDisplay(result);
        }
    }
    
    /**
     * Run comprehensive security analysis
     */
    private void runSecurityAnalysis() {
        String token = rawTokenArea.getText().trim();
        if (token.isEmpty()) {
            validationResultsArea.setText("No token available for analysis.");
            return;
        }
        
        validationResultsArea.setText("Running security analysis...\n");
        
        CompletableFuture.supplyAsync(() -> performValidation(token))
            .thenAccept(result -> SwingUtilities.invokeLater(() -> displayDetailedAnalysis(result)));
    }
    
    /**
     * Display detailed security analysis
     */
    private void displayDetailedAnalysis(ValidationResult result) {
        StringBuilder analysis = new StringBuilder();
        
        analysis.append("=== JWT Security Analysis Report ===").append("\n\n");
        analysis.append("Token Status: ").append(result.getStatusMessage()).append("\n");
        analysis.append("Analysis Time: ").append(new Date()).append("\n\n");
        
        if (result.getAssessment() != null) {
            AdvancedVulnerabilityDetector.VulnerabilityAssessment assessment = result.getAssessment();
            
            // Risk score
            analysis.append("=== Risk Assessment ===").append("\n");
            analysis.append("Overall Risk Level: ").append(assessment.getRiskScore().getRiskLevel()).append("\n");
            analysis.append("Risk Score: ").append(String.format("%.1f/10", assessment.getRiskScore().getOverallScore())).append("\n");
            analysis.append("Algorithm Risk: ").append(String.format("%.1f/10", assessment.getRiskScore().getAlgorithmRisk())).append("\n");
            analysis.append("Configuration Risk: ").append(String.format("%.1f/10", assessment.getRiskScore().getConfigurationRisk())).append("\n");
            analysis.append("Implementation Risk: ").append(String.format("%.1f/10", assessment.getRiskScore().getImplementationRisk())).append("\n\n");
            
            // Critical vulnerabilities
            if (!assessment.getCriticalVulnerabilities().isEmpty()) {
                analysis.append("=== CRITICAL VULNERABILITIES ===").append("\n");
                for (SecurityFinding finding : assessment.getCriticalVulnerabilities()) {
                    analysis.append("• ").append(finding.getTitle()).append(": ").append(finding.getMessage()).append("\n");
                    if (finding.getDetails() != null && !finding.getDetails().isEmpty()) {
                        analysis.append("  Details: ").append(finding.getDetails()).append("\n");
                    }
                }
                analysis.append("\n");
            }
            
            // Algorithm weaknesses
            if (!assessment.getAlgorithmWeaknesses().isEmpty()) {
                analysis.append("=== Algorithm Weaknesses ===").append("\n");
                for (SecurityFinding finding : assessment.getAlgorithmWeaknesses()) {
                    analysis.append("• ").append(finding.getTitle()).append(": ").append(finding.getMessage()).append("\n");
                }
                analysis.append("\n");
            }
            
            // Possible attacks
            if (!assessment.getPossibleAttacks().isEmpty()) {
                analysis.append("=== Possible Attack Vectors ===").append("\n");
                for (Map.Entry<String, AdvancedVulnerabilityDetector.AttackVector> entry : assessment.getPossibleAttacks().entrySet()) {
                    AdvancedVulnerabilityDetector.AttackVector attack = entry.getValue();
                    analysis.append("Attack: ").append(attack.getName()).append("\n");
                    analysis.append("  Description: ").append(attack.getDescription()).append("\n");
                    analysis.append("  Success Probability: ").append(String.format("%.0f%%", attack.getSuccessProbability() * 100)).append("\n");
                    analysis.append("  Impact: ").append(attack.getImpact()).append("\n");
                    analysis.append("  Mitigation: ").append(attack.getMitigation()).append("\n\n");
                }
            }
            
            // Configuration issues
            if (!assessment.getConfigurationIssues().isEmpty()) {
                analysis.append("=== Configuration Issues ===").append("\n");
                for (SecurityFinding finding : assessment.getConfigurationIssues()) {
                    analysis.append("• ").append(finding.getTitle()).append(": ").append(finding.getMessage()).append("\n");
                }
                analysis.append("\n");
            }
        }
        
        analysis.append(result.getDetailedMessage());
        
        validationResultsArea.setText(analysis.toString());
        validationResultsArea.setCaretPosition(0); // Scroll to top
    }
    
    /**
     * Update validation results display
     */
    private void updateValidationResultsDisplay(ValidationResult result) {
        if (result.getAssessment() != null) {
            displayDetailedAnalysis(result);
        } else {
            validationResultsArea.setText(result.getDetailedMessage());
        }
    }
    
    /**
     * Sign current token with specified algorithm and key
     */
    private void signCurrentToken() {
        String algorithm = (String) algorithmCombo.getSelectedItem();
        String key = signatureKeyArea.getText().trim();
        
        if (algorithm == null) {
            updateStatus("No algorithm selected", ThemeManager.getErrorColor());
            return;
        }
        
        if ("none".equals(algorithm)) {
            signWithNoneAlgorithm();
            return;
        }
        
        if (key.isEmpty()) {
            updateStatus("No signing key provided", ThemeManager.getErrorColor());
            return;
        }
        
        try {
            String headerJson = headerArea.getText().trim();
            String payloadJson = payloadArea.getText().trim();
            
            if (headerJson.isEmpty() || payloadJson.isEmpty()) {
                updateStatus("Header and payload required for signing", ThemeManager.getErrorColor());
                return;
            }
            
            // Update algorithm in header
            headerJson = updateJsonAlgorithm(headerJson, algorithm);
            headerArea.setText(formatJson(headerJson));
            
            // Encode components
            String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
            
            // Create signing input
            String signingInput = encodedHeader + "." + encodedPayload;
            
            // Sign based on algorithm family
            String signature;
            if (algorithm.startsWith("HS")) {
                signature = signWithHMAC(signingInput, key, algorithm);
            } else {
                updateStatus("Asymmetric algorithms not yet implemented", ThemeManager.getWarningColor());
                return;
            }
            
            // Update signature and token
            signatureArea.setText(signature);
            
            String signedToken = encodedHeader + "." + encodedPayload + "." + signature;
            isUpdating = true;
            rawTokenArea.setText(signedToken);
            isUpdating = false;
            
            updateStatus("Token signed successfully with " + algorithm, ThemeManager.getSuccessColor());
            
        } catch (Exception e) {
            logger.error("Failed to sign token: %s", e.getMessage());
            updateStatus("Signing failed: " + e.getMessage(), ThemeManager.getErrorColor());
        }
    }
    
    /**
     * Sign with HMAC algorithm
     */
    private String signWithHMAC(String signingInput, String secret, String algorithm) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        
        String macAlgorithm;
        switch (algorithm) {
            case "HS256":
                macAlgorithm = "HmacSHA256";
                break;
            case "HS384":
                macAlgorithm = "HmacSHA384";
                break;
            case "HS512":
                macAlgorithm = "HmacSHA512";
                break;
            default:
                throw new IllegalArgumentException("Unsupported HMAC algorithm: " + algorithm);
        }
        
        Mac mac = Mac.getInstance(macAlgorithm);
        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlgorithm);
        mac.init(secretKey);
        
        byte[] signature = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }
    
    /**
     * Sign with 'none' algorithm (remove signature)
     */
    private void signWithNoneAlgorithm() {
        try {
            String headerJson = headerArea.getText().trim();
            String payloadJson = payloadArea.getText().trim();
            
            if (headerJson.isEmpty() || payloadJson.isEmpty()) {
                updateStatus("Header and payload required", ThemeManager.getErrorColor());
                return;
            }
            
            // Update algorithm in header to 'none'
            headerJson = updateJsonAlgorithm(headerJson, "none");
            headerArea.setText(formatJson(headerJson));
            
            // Encode components
            String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
            
            // Clear signature
            signatureArea.setText("");
            
            // Create unsigned token
            String unsignedToken = encodedHeader + "." + encodedPayload + ".";
            isUpdating = true;
            rawTokenArea.setText(unsignedToken);
            isUpdating = false;
            
            updateStatus("Token signed with 'none' algorithm (unsigned)", ThemeManager.getWarningColor());
            
        } catch (Exception e) {
            logger.error("Failed to create unsigned token: %s", e.getMessage());
            updateStatus("Failed to create unsigned token", ThemeManager.getErrorColor());
        }
    }
    
    /**
     * Schedule auto-signing when auto-sign is enabled
     */
    private void scheduleAutoSign() {
        if (!autoSignCheckbox.isSelected()) return;
        
        // Delay auto-sign to avoid excessive signing during rapid typing
        SwingUtilities.invokeLater(() -> {
            try {
                Thread.sleep(300); // 300ms delay
                if (autoSignCheckbox.isSelected() && hasValidComponents()) {
                    signCurrentToken();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }
    
    /**
     * Generate a signing key based on selected algorithm
     */
    private void generateSigningKey() {
        String algorithm = (String) algorithmCombo.getSelectedItem();
        if (algorithm == null) return;
        
        try {
            if (algorithm.startsWith("HS")) {
                // Generate random HMAC secret
                byte[] randomBytes = new byte[32]; // 256 bits
                new SecureRandom().nextBytes(randomBytes);
                String secret = Base64.getEncoder().encodeToString(randomBytes);
                signatureKeyArea.setText(secret);
                updateStatus("Generated HMAC secret", ThemeManager.getSuccessColor());
            } else {
                updateStatus("Key generation for " + algorithm + " not yet implemented", ThemeManager.getWarningColor());
            }
        } catch (Exception e) {
            logger.error("Failed to generate key: %s", e.getMessage());
            updateStatus("Key generation failed", ThemeManager.getErrorColor());
        }
    }
    
    /**
     * Load signing key from file
     */
    private void loadSigningKey() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Load Signing Key");
        
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                String keyContent = new String(
                    java.nio.file.Files.readAllBytes(fileChooser.getSelectedFile().toPath()),
                    StandardCharsets.UTF_8
                );
                signatureKeyArea.setText(keyContent.trim());
                updateStatus("Key loaded from " + fileChooser.getSelectedFile().getName(), ThemeManager.getSuccessColor());
            } catch (Exception e) {
                logger.error("Failed to load key: %s", e.getMessage());
                updateStatus("Failed to load key file", ThemeManager.getErrorColor());
            }
        }
    }
    
    /**
     * Export analysis results to file
     */
    private void exportAnalysisResults() {
        String results = validationResultsArea.getText();
        if (results.isEmpty()) {
            updateStatus("No analysis results to export", ThemeManager.getWarningColor());
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Analysis Results");
        fileChooser.setSelectedFile(new java.io.File("jwt_analysis_" + System.currentTimeMillis() + ".txt"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                java.nio.file.Files.write(
                    fileChooser.getSelectedFile().toPath(),
                    results.getBytes(StandardCharsets.UTF_8)
                );
                updateStatus("Analysis exported to " + fileChooser.getSelectedFile().getName(), ThemeManager.getSuccessColor());
            } catch (Exception e) {
                logger.error("Failed to export analysis: %s", e.getMessage());
                updateStatus("Export failed", ThemeManager.getErrorColor());
            }
        }
    }
    
    /**
     * Reset editor to initial state
     */
    private void resetEditor() {
        isUpdating = true;
        
        rawTokenArea.setText("");
        headerArea.setText("");
        payloadArea.setText("");
        signatureArea.setText("");
        validationResultsArea.setText("");
        signatureKeyArea.setText("");
        
        algorithmCombo.setSelectedItem("HS256");
        
        currentParsedJWT = null;
        hasUnsavedChanges = false;
        lastValidToken = "";
        
        updateStatus("Editor reset", ThemeManager.getInfoColor());
        updateValidationStatus("No token loaded", ThemeManager.getDefaultColor());
        
        isUpdating = false;
    }
    
    /**
     * Load a JWT token into the editor
     */
    public void loadToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return;
        }
        
        SwingUtilities.invokeLater(() -> {
            rawTokenArea.setText(token.trim());
            // The document listener will handle parsing and updating components
        });
    }
    
    /**
     * Get the current token from the editor
     */
    public String getCurrentToken() {
        return rawTokenArea.getText().trim();
    }
    
    /**
     * Check if editor has a valid token
     */
    public boolean hasValidToken() {
        return currentParsedJWT != null && currentParsedJWT.getValidation().isValid();
    }
    
    // Utility methods
    
    private void clearComponents() {
        isUpdating = true;
        headerArea.setText("");
        payloadArea.setText("");
        signatureArea.setText("");
        isUpdating = false;
    }
    
    private boolean hasValidComponents() {
        return !headerArea.getText().trim().isEmpty() && !payloadArea.getText().trim().isEmpty();
    }
    
    private void updateStatus(String message, Color color) {
        statusLabel.setText(message);
        statusLabel.setForeground(color);
    }
    
    private void updateValidationStatus(String message, Color color) {
        validationLabel.setText(message);
        validationLabel.setForeground(color);
    }
    
    private void updateAlgorithmInHeader(String algorithm) {
        if (isUpdating) return;
        
        String headerJson = headerArea.getText().trim();
        if (!headerJson.isEmpty()) {
            try {
                String updatedHeader = updateJsonAlgorithm(headerJson, algorithm);
                isUpdating = true;
                headerArea.setText(formatJson(updatedHeader));
                isUpdating = false;
            } catch (Exception e) {
                logger.warn("Failed to update algorithm in header: %s", e.getMessage());
            }
        }
    }
    
    private void updateKeyAreaPlaceholder(String algorithm) {
        String description = algorithmDescriptions.get(algorithm);
        if (description != null) {
            signatureKeyArea.setToolTipText(description);
        }
        
        if (algorithm.startsWith("HS")) {
            if (signatureKeyArea.getText().trim().isEmpty()) {
                signatureKeyArea.setText("# Enter HMAC secret here\n# Can be plain text or Base64 encoded");
            }
        } else if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
            if (signatureKeyArea.getText().trim().isEmpty()) {
                signatureKeyArea.setText("# Enter RSA private key in PEM format\n-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----");
            }
        } else if (algorithm.startsWith("ES")) {
            if (signatureKeyArea.getText().trim().isEmpty()) {
                signatureKeyArea.setText("# Enter ECDSA private key in PEM format\n-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----");
            }
        } else if ("none".equals(algorithm)) {
            signatureKeyArea.setText("# No key required for 'none' algorithm");
        }
    }
    
    private String formatJson(String json) {
        // Simple JSON formatting for better readability
        if (json == null || json.trim().isEmpty()) {
            return "";
        }
        
        try {
            // Basic formatting - add newlines and indentation
            json = json.trim();
            if (json.startsWith("{") && json.endsWith("}")) {
                StringBuilder formatted = new StringBuilder();
                formatted.append("{\n");
                
                String content = json.substring(1, json.length() - 1);
                String[] pairs = content.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                
                for (int i = 0; i < pairs.length; i++) {
                    formatted.append("  ").append(pairs[i].trim());
                    if (i < pairs.length - 1) {
                        formatted.append(",");
                    }
                    formatted.append("\n");
                }
                
                formatted.append("}");
                return formatted.toString();
            }
            return json;
        } catch (Exception e) {
            return json; // Return original if formatting fails
        }
    }
    
    private String updateJsonAlgorithm(String json, String algorithm) {
        // Simple algorithm update in JSON
        try {
            if (json.contains("\"alg\"")) {
                return json.replaceFirst("\"alg\"\\s*:\\s*\"[^\"]*\"", "\"alg\": \"" + algorithm + "\"");
            } else {
                // Add algorithm if not present
                if (json.trim().equals("{}")) {
                    return "{\"alg\": \"" + algorithm + "\"}";
                } else {
                    int insertPos = json.indexOf('{') + 1;
                    return json.substring(0, insertPos) + "\"alg\": \"" + algorithm + "\", " + json.substring(insertPos);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to update JSON algorithm: %s", e.getMessage());
            return json;
        }
    }
    
    /**
     * Cleanup resources when editor is disposed
     */
    public void dispose() {
        if (validationExecutor != null && !validationExecutor.isShutdown()) {
            validationExecutor.shutdown();
            try {
                if (!validationExecutor.awaitTermination(1, TimeUnit.SECONDS)) {
                    validationExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                validationExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        
        if (currentValidation != null && !currentValidation.isDone()) {
            currentValidation.cancel(true);
        }
        
        resourceTracker.releaseResource(editorId);
        
        logger.debug("Interactive JWT Editor disposed: %s", editorId);
    }
}
