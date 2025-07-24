import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.EditorOptions;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class BruteForce {
    private MontoyaApi api;
    private JPanel mainPanel;
    private HttpRequestEditor requestEditor;
    private JTextArea wordlistArea;
    private JLabel wordlistLabel;
    private JButton selectWordlistButton;
    private JButton startBruteForceButton;
    private JButton clearButton;
    private JProgressBar progressBar;
    private JTextArea resultsArea;
    private JLabel statusLabel;
    private File selectedWordlistFile;
    private HttpRequestResponse currentRequestResponse;
    private String originalJWT;
    private boolean isRunning = false;
    private Thread bruteForceThread;
    
    // JWT pattern for detection
    private static final Pattern JWT_PATTERN = Pattern.compile("(eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*)");
    
    public BruteForce(MontoyaApi api) {
        this.api = api;
        initializeUI();
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Create top panel with request viewer
        JPanel topPanel = createRequestPanel();
        
        // Create middle panel with wordlist selection
        JPanel middlePanel = createWordlistPanel();
        
        // Create bottom panel with results and controls
        JPanel bottomPanel = createResultsPanel();
        
        // Add panels to main panel
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(middlePanel, BorderLayout.CENTER);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createRequestPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Request for Brute Force"));
        panel.setPreferredSize(new Dimension(0, 250));
        
        // Initialize request editor
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        
        // Create info panel
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel("Send a request containing a JWT token from Proxy using right-click menu");
        infoLabel.setFont(infoLabel.getFont().deriveFont(Font.ITALIC));
        infoPanel.add(infoLabel);
        
        panel.add(infoPanel, BorderLayout.NORTH);
        panel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createWordlistPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("JWT Signing Key Wordlist"));
        panel.setPreferredSize(new Dimension(0, 200));
        
        // Top section for file selection
        JPanel filePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectWordlistButton = new JButton("Select Wordlist File");
        selectWordlistButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectWordlistFile();
            }
        });
        
        wordlistLabel = new JLabel("No wordlist selected");
        filePanel.add(selectWordlistButton);
        filePanel.add(wordlistLabel);
        
        // Center section for wordlist preview
        wordlistArea = new JTextArea();
        wordlistArea.setEditable(false);
        ThemeManager.styleMonospaceTextArea(wordlistArea);
        wordlistArea.setText("Select a wordlist file to see preview...");
        JScrollPane wordlistScroll = new JScrollPane(wordlistArea);
        wordlistScroll.setPreferredSize(new Dimension(0, 150));
        
        panel.add(filePanel, BorderLayout.NORTH);
        panel.add(wordlistScroll, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setPreferredSize(new Dimension(0, 300));
        
        // Control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        startBruteForceButton = new JButton("Start Brute Force");
        startBruteForceButton.setEnabled(false);
        startBruteForceButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!isRunning) {
                    startBruteForce();
                } else {
                    stopBruteForce();
                }
            }
        });
        
        clearButton = new JButton("Clear Results");
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                clearResults();
            }
        });
        
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        progressBar.setPreferredSize(new Dimension(200, 25));
        
        statusLabel = new JLabel("Status: Ready");
        
        controlPanel.add(startBruteForceButton);
        controlPanel.add(clearButton);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(new JLabel("Progress:"));
        controlPanel.add(progressBar);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(statusLabel);
        
        // Results area
        resultsArea = new JTextArea();
        resultsArea.setEditable(false);
        ThemeManager.styleMonospaceTextArea(resultsArea);
        resultsArea.setText("Results will appear here...");
        JScrollPane resultsScroll = new JScrollPane(resultsArea);
        resultsScroll.setBorder(BorderFactory.createTitledBorder("Brute Force Results"));
        
        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(resultsScroll, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void selectWordlistFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select JWT Signing Key Wordlist");
        
        // Ensure all files are visible by default
        fileChooser.setAcceptAllFileFilterUsed(true);
        
        // Create and add text filter
        FileNameExtensionFilter txtFilter = new FileNameExtensionFilter("Text files (*.txt)", "txt");
        fileChooser.addChoosableFileFilter(txtFilter);
        
        // Set the built-in "All Files" filter as the default
        // This ensures immediate file visibility
        fileChooser.setFileFilter(fileChooser.getAcceptAllFileFilter());
        
        // Force the file chooser to rescan the directory
        fileChooser.rescanCurrentDirectory();
        
        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            selectedWordlistFile = fileChooser.getSelectedFile();
            loadWordlistPreview();
            updateStartButtonState();
        }
    }
    
    private void loadWordlistPreview() {
        if (selectedWordlistFile == null) return;
        
        try {
            List<String> lines = Files.readAllLines(selectedWordlistFile.toPath());
            int totalLines = lines.size();
            
            // Update label
            wordlistLabel.setText(selectedWordlistFile.getName() + " (" + totalLines + " keys)");
            
            // Show preview (first 20 lines)
            StringBuilder preview = new StringBuilder();
            preview.append("Wordlist Preview (showing first 20 keys):\n\n");
            
            int previewCount = Math.min(20, totalLines);
            for (int i = 0; i < previewCount; i++) {
                preview.append((i + 1)).append(". ").append(lines.get(i)).append("\n");
            }
            
            if (totalLines > 20) {
                preview.append("\n... and ").append(totalLines - 20).append(" more keys");
            }
            
            wordlistArea.setText(preview.toString());
            
            api.logging().logToOutput("Loaded wordlist: " + selectedWordlistFile.getName() + " with " + totalLines + " keys");
            
        } catch (IOException e) {
            api.logging().logToError("Error loading wordlist: " + e.getMessage());
            JOptionPane.showMessageDialog(mainPanel, 
                "Error loading wordlist: " + e.getMessage(), 
                "File Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void updateStartButtonState() {
        boolean canStart = selectedWordlistFile != null && 
                          currentRequestResponse != null && 
                          originalJWT != null && 
                          !isRunning;
        startBruteForceButton.setEnabled(canStart);
    }
    
    private void startBruteForce() {
        if (selectedWordlistFile == null || currentRequestResponse == null || originalJWT == null) {
            JOptionPane.showMessageDialog(mainPanel, 
                "Please ensure you have:\n" +
                "1. A request with a JWT token\n" +
                "2. A selected wordlist file", 
                "Missing Requirements", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        isRunning = true;
        startBruteForceButton.setText("Stop Brute Force");
        clearButton.setEnabled(false);
        
        // Clear previous results
        resultsArea.setText("Starting JWT signing key brute force...\n\n");
        statusLabel.setText("Status: Running");
        
        // Start brute force in background thread
        bruteForceThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    performBruteForce();
                } catch (Exception e) {
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            appendResult("Error during brute force: " + e.getMessage());
                        }
                    });
                    api.logging().logToError("JWT Brute Force error: " + e.getMessage());
                }
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        finishBruteForce();
                    }
                });
            }
        });
        bruteForceThread.start();
    }
    
    private void performBruteForce() {
        try {
            List<String> keys = Files.readAllLines(selectedWordlistFile.toPath());
            int totalKeys = keys.size();
            
            appendResult("Loaded " + totalKeys + " signing keys from wordlist");
            appendResult("Original JWT: " + originalJWT.substring(0, Math.min(50, originalJWT.length())) + "...");
            appendResult("Starting brute force attack...");
            appendResult("");
            
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    progressBar.setMaximum(totalKeys);
                    progressBar.setValue(0);
                }
            });
            
            for (int i = 0; i < totalKeys; i++) {
                if (Thread.currentThread().isInterrupted()) {
                    appendResult("Brute force stopped by user");
                    break;
                }
                
                String key = keys.get(i).trim();
                if (key.isEmpty()) continue;
                
                final int currentIndex = i;
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        progressBar.setValue(currentIndex + 1);
                        progressBar.setString("Testing key " + (currentIndex + 1) + "/" + totalKeys);
                        statusLabel.setText("Status: Testing key " + (currentIndex + 1) + "/" + totalKeys);
                    }
                });
                
                // Test the key
                boolean isValid = testSigningKey(key);
                
                if (isValid) {
                    appendResult("*** FOUND VALID SIGNING KEY! ***");
                    appendResult("Key: " + key);
                    appendResult("Position in wordlist: " + (i + 1));
                    appendResult("");
                    
                    // Log to Burp output for easy copying
                    api.logging().logToOutput("JWT Brute Force: FOUND VALID SIGNING KEY: " + key);
                    
                    final String finalKey = key;
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            statusLabel.setText("Status: FOUND VALID KEY!");
                            JOptionPane.showMessageDialog(mainPanel, 
                                "Valid signing key found!\n\nKey: " + finalKey + "\n\nSee results panel for details.", 
                                "Brute Force Success", 
                                JOptionPane.INFORMATION_MESSAGE);
                        }
                    });
                    
                    break; // Stop on first valid key found
                }
                
                // Update progress periodically
                if ((i + 1) % 100 == 0) {
                    appendResult("Tested " + (i + 1) + "/" + totalKeys + " keys...");
                }
                
                // Small delay to prevent overwhelming the target
                Thread.sleep(10);
            }
            
            appendResult("");
            appendResult("Brute force completed.");
            
        } catch (Exception e) {
            appendResult("Error during brute force: " + e.getMessage());
            api.logging().logToError("JWT Brute Force error: " + e.getMessage());
        }
    }
    
    private void appendResult(String message) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                resultsArea.append(message + "\n");
                resultsArea.setCaretPosition(resultsArea.getDocument().getLength());
            }
        });
    }
    
    private boolean testSigningKey(String key) {
        try {
            // Use JWTUtils to verify the JWT with the provided key
            return JWTUtils.verifyJWTSignature(originalJWT, key);
            
        } catch (Exception e) {
            // If any error occurs during verification, the key is invalid
            return false;
        }
    }
    
    private void stopBruteForce() {
        if (bruteForceThread != null && bruteForceThread.isAlive()) {
            bruteForceThread.interrupt();
            appendResult("Brute force stopped by user.");
        }
        finishBruteForce();
    }
    
    private void finishBruteForce() {
        isRunning = false;
        startBruteForceButton.setText("Start Brute Force");
        clearButton.setEnabled(true);
        
        SwingUtilities.invokeLater(() -> {
            progressBar.setString("Completed");
            statusLabel.setText("Status: Completed");
            updateStartButtonState();
        });
    }
    
    private void clearResults() {
        resultsArea.setText("Results will appear here...");
        progressBar.setValue(0);
        progressBar.setString("Ready");
        statusLabel.setText("Status: Ready");
    }
    
    /**
     * Process a request sent from the context menu
     */
    public void processRequest(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            api.logging().logToError("BruteForce: Received null request");
            return;
        }
        
        try {
            this.currentRequestResponse = requestResponse;
            
            // Update the request editor
            requestEditor.setRequest(requestResponse.request());
            
            // Extract JWT token from the request
            String requestString = requestResponse.request().toString();
            this.originalJWT = extractJWTFromRequest(requestString);
            
            if (originalJWT != null) {
                api.logging().logToOutput("BruteForce: JWT token extracted: " + originalJWT.substring(0, Math.min(50, originalJWT.length())) + "...");
                
                // Token extracted successfully - no popup needed, just log
                api.logging().logToOutput("BruteForce: Request loaded with JWT token, ready for brute force");
            } else {
                api.logging().logToOutput("BruteForce: No JWT token found in request");
                // Log warning instead of showing popup
                api.logging().logToError("BruteForce: No JWT token found in the request. Please send a request containing a Bearer token with JWT format.");
            }
            
            updateStartButtonState();
            
        } catch (Exception e) {
            api.logging().logToError("Error processing request in BruteForce: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private String extractJWTFromRequest(String requestString) {
        try {
            // Look for JWT in Authorization header
            Matcher matcher = JWT_PATTERN.matcher(requestString);
            if (matcher.find()) {
                return matcher.group(1);
            }
            return null;
        } catch (Exception e) {
            api.logging().logToError("Error extracting JWT: " + e.getMessage());
            return null;
        }
    }
    
    public JPanel getUI() {
        return mainPanel;
    }
    
    /**
     * Stop all running threads for proper extension cleanup
     */
    public void stopAllThreads() {
        if (bruteForceThread != null && bruteForceThread.isAlive()) {
            bruteForceThread.interrupt();
            try {
                // Wait for thread to finish with timeout
                bruteForceThread.join(1000);
            } catch (InterruptedException e) {
                api.logging().logToError("Error stopping brute force thread: " + e.getMessage());
            }
        }
        isRunning = false;
    }
}
