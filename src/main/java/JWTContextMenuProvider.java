import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Timer;
import java.util.TimerTask;

public class JWTContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final JWTTools jwtTools;
    private final BruteForce bruteForce;
    private final AttackTools attackTools;
    
    public JWTContextMenuProvider(MontoyaApi api, JWTTools jwtTools) {
        this.api = api;
        this.jwtTools = jwtTools;
        this.bruteForce = null; // Will be set later
        this.attackTools = null; // Will be set later
    }
    
    public JWTContextMenuProvider(MontoyaApi api, JWTTools jwtTools, BruteForce bruteForce) {
        this.api = api;
        this.jwtTools = jwtTools;
        this.bruteForce = bruteForce;
        this.attackTools = null; // Will be set later
    }
    
    public JWTContextMenuProvider(MontoyaApi api, JWTTools jwtTools, BruteForce bruteForce, AttackTools attackTools) {
        this.api = api;
        this.jwtTools = jwtTools;
        this.bruteForce = bruteForce;
        this.attackTools = attackTools;
    }
    
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        
        try {
            // Check if we have selected requests/responses from history
            List<HttpRequestResponse> requestResponses = event.selectedRequestResponses();
            
            // Also check if we're in a request/response editor (like Proxy request viewer)
            HttpRequestResponse currentRequestResponse = null;
            
            if (!requestResponses.isEmpty()) {
                // Use selected requests from history
                currentRequestResponse = requestResponses.get(0);
            } else if (event.messageEditorRequestResponse().isPresent()) {
                // Use current request/response from editor (Proxy request viewer)
                MessageEditorHttpRequestResponse editorRequestResponse = event.messageEditorRequestResponse().get();
                // Extract the underlying HttpRequestResponse directly
                currentRequestResponse = editorRequestResponse.requestResponse();
                // Create a list with just this one for consistency
                requestResponses = new ArrayList<>();
                requestResponses.add(currentRequestResponse);
            }
            
            if (currentRequestResponse != null) {
                // Make variables final for inner class access
                final HttpRequestResponse finalCurrentRequestResponse = currentRequestResponse;
                
                // Create single "Send to JWT Tools" menu item
                JMenuItem sendToJWTTools = new JMenuItem("Send to JWT Tools");
                sendToJWTTools.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        sendToAllJWTTools(finalCurrentRequestResponse);
                    }
                });
                
                menuItems.add(sendToJWTTools);
            }
        } catch (Exception ex) {
            api.logging().logToError("Error creating context menu: " + ex.getMessage());
            ex.printStackTrace();
        }
        
        return menuItems;
    }
    
    private void sendToAllJWTTools(HttpRequestResponse requestResponse) {
        try {
            api.logging().logToOutput("Context Menu: sendToAllJWTTools called");
            
            // Show status indicator that requests are being sent
            JWTStatusIndicator.showRequestsSentToTools();
            
            // Process on UI thread without confirmation popups
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Send to JWT Analysis (always available)
                        if (jwtTools != null) {
                            jwtTools.processRequest(requestResponse);
                            api.logging().logToOutput("JWT Manager: Request sent to JWT Analysis");
                        }
                        
                        // Send to Brute Force if available
                        if (bruteForce != null) {
                            bruteForce.processRequest(requestResponse);
                            api.logging().logToOutput("JWT Manager: Request sent to Brute Force");
                        }
                        
                        // Send to Attack Tools if available
                        if (attackTools != null) {
                            attackTools.processRequest(requestResponse);
                            api.logging().logToOutput("JWT Manager: Request sent to Attack Tools");
                        }
                        
                        // Show completion status after a short delay
                        Timer completionTimer = new Timer();
                        completionTimer.schedule(new TimerTask() {
                            @Override
                            public void run() {
                                JWTStatusIndicator.showSuccess("Requests processed");
                            }
                        }, 1000);
                        
                        // Log completion - no popup notification
                        api.logging().logToOutput("JWT Manager: Request sent to all available JWT tools - status indicator active");
                        
                    } catch (Exception e) {
                        api.logging().logToError("Error in sendToAllJWTTools runnable: " + e.getMessage());
                        e.printStackTrace();
                    }
                }
            });
            
        } catch (Exception e) {
            api.logging().logToError("Error sending request to all JWT tools: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void sendToJWTAnalysis(HttpRequestResponse requestResponse) {
        try {
            api.logging().logToOutput("Context Menu: sendToJWTAnalysis called");
            
            // Debug: Check what we're sending
            if (requestResponse != null) {
                api.logging().logToOutput("Context Menu: RequestResponse is not null");
                if (requestResponse.request() != null) {
                    api.logging().logToOutput("Context Menu: Request is not null, method: " + requestResponse.request().method());
                } else {
                    api.logging().logToOutput("Context Menu: Request is null!");
                }
                if (requestResponse.response() != null) {
                    api.logging().logToOutput("Context Menu: Response is not null, status: " + requestResponse.response().statusCode());
                } else {
                    api.logging().logToOutput("Context Menu: Response is null");
                }
            } else {
                api.logging().logToOutput("Context Menu: RequestResponse is null!");
            }
            
            // Switch to JWT Manager extension tab
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Process the request in JWT Analysis
                        jwtTools.processRequest(requestResponse);
                        
                        // Log the action
                        api.logging().logToOutput("JWT Manager: Request sent to JWT Analysis from context menu");
                    } catch (Exception e) {
                        api.logging().logToError("Error in sendToJWTAnalysis runnable: " + e.getMessage());
                        e.printStackTrace();
                        showErrorNotification("Error", "Failed to process request: " + e.getMessage());
                    }
                }
            });
            
        } catch (Exception e) {
            api.logging().logToError("Error sending request to JWT Analysis: " + e.getMessage());
            e.printStackTrace();
            showErrorNotification("Error", "Failed to send request to JWT Analysis: " + e.getMessage());
        }
    }
    
    private void sendToBruteForce(HttpRequestResponse requestResponse) {
        try {
            api.logging().logToOutput("Context Menu: sendToBruteForce called");
            
            // Debug: Check what we're sending
            if (requestResponse != null) {
                api.logging().logToOutput("Context Menu: RequestResponse is not null for Brute Force");
                if (requestResponse.request() != null) {
                    api.logging().logToOutput("Context Menu: Request is not null, method: " + requestResponse.request().method());
                } else {
                    api.logging().logToOutput("Context Menu: Request is null!");
                }
            } else {
                api.logging().logToOutput("Context Menu: RequestResponse is null!");
            }
            
            // Process on UI thread
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Process the request in Brute Force
                        bruteForce.processRequest(requestResponse);
                        
                        // Log the action
                        api.logging().logToOutput("JWT Manager: Request sent to Brute Force from context menu");
                    } catch (Exception e) {
                        api.logging().logToError("Error in sendToBruteForce runnable: " + e.getMessage());
                        e.printStackTrace();
                        showErrorNotification("Error", "Failed to process request in Brute Force: " + e.getMessage());
                    }
                }
            });
            
        } catch (Exception e) {
            api.logging().logToError("Error sending request to Brute Force: " + e.getMessage());
            e.printStackTrace();
            showErrorNotification("Error", "Failed to send request to Brute Force: " + e.getMessage());
        }
    }
    
    private void sendToAttackTools(HttpRequestResponse requestResponse) {
        try {
            api.logging().logToOutput("Context Menu: sendToAttackTools called");
            
            // Debug: Check what we're sending
            if (requestResponse != null) {
                api.logging().logToOutput("Context Menu: RequestResponse is not null for Attack Tools");
                if (requestResponse.request() != null) {
                    api.logging().logToOutput("Context Menu: Request is not null, method: " + requestResponse.request().method());
                } else {
                    api.logging().logToOutput("Context Menu: Request is null!");
                }
            } else {
                api.logging().logToOutput("Context Menu: RequestResponse is null!");
            }
            
            // Process on UI thread - send to existing Attack Tools tab instead of opening dialog
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Send to the existing Attack Tools instance in the main extension
                        if (attackTools != null) {
                            attackTools.processRequest(requestResponse);
                        } else {
                            api.logging().logToError("Attack Tools not available. Please check JWT Manager extension initialization.");
                        }
                        
                        // Log the action
                        api.logging().logToOutput("JWT Manager: Request sent to Attack Tools tab from context menu");
                        
                    } catch (Exception e) {
                        api.logging().logToError("Error in sendToAttackTools runnable: " + e.getMessage());
                        e.printStackTrace();
                        showErrorNotification("Error", "Failed to send to Attack Tools tab: " + e.getMessage());
                    }
                }
            });
            
        } catch (Exception e) {
            api.logging().logToError("Error sending request to Attack Tools: " + e.getMessage());
            e.printStackTrace();
            showErrorNotification("Error", "Failed to send request to Attack Tools: " + e.getMessage());
        }
    }

    
    private void performQuickJWTAnalysis(HttpRequestResponse requestResponse) {
        try {
            String analysisResult = quickAnalyzeForJWT(requestResponse);
            
            // Show result in a dialog
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    try {
                        JOptionPane.showMessageDialog(
                            null,
                            analysisResult,
                            "Quick JWT Analysis",
                            JOptionPane.INFORMATION_MESSAGE
                        );
                    } catch (Exception e) {
                        api.logging().logToError("Error showing quick analysis dialog: " + e.getMessage());
                    }
                }
            });
            
        } catch (Exception e) {
            api.logging().logToError("Error in quick JWT analysis: " + e.getMessage());
            showErrorNotification("Analysis Error", "Failed to analyze request: " + e.getMessage());
        }
    }
    
    private void performBatchJWTAnalysis(List<HttpRequestResponse> requestResponses) {
        try {
            StringBuilder results = new StringBuilder();
            results.append("JWT Analysis Results for ").append(requestResponses.size()).append(" requests:\\n\\n");
            
            int jwtCount = 0;
            for (int i = 0; i < requestResponses.size(); i++) {
                HttpRequestResponse rr = requestResponses.get(i);
                String analysis = quickAnalyzeForJWT(rr);
                
                if (!analysis.contains("No JWT")) {
                    jwtCount++;
                    results.append("Request #").append(i + 1).append(": ").append(analysis).append("\\n");
                }
            }
            
            if (jwtCount == 0) {
                results.append("No JWT tokens found in any of the selected requests.");
            } else {
                results.insert(0, "Found JWT tokens in " + jwtCount + " out of " + requestResponses.size() + " requests.\\n\\n");
            }
            
            // Show results in a dialog
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    try {
                        JTextArea textArea = new JTextArea(results.toString());
                        textArea.setEditable(false);
                        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
                        
                        JScrollPane scrollPane = new JScrollPane(textArea);
                        scrollPane.setPreferredSize(new Dimension(600, 400));
                        
                        JOptionPane.showMessageDialog(
                            null,
                            scrollPane,
                            "Batch JWT Analysis Results",
                            JOptionPane.INFORMATION_MESSAGE
                        );
                    } catch (Exception e) {
                        api.logging().logToError("Error showing batch analysis dialog: " + e.getMessage());
                    }
                }
            });
            
        } catch (Exception e) {
            api.logging().logToError("Error in batch JWT analysis: " + e.getMessage());
            showErrorNotification("Batch Analysis Error", "Failed to analyze requests: " + e.getMessage());
        }
    }
    
    private String quickAnalyzeForJWT(HttpRequestResponse requestResponse) {
        try {
            // Simple JWT detection
            String requestString = requestResponse.request() != null ? requestResponse.request().toString() : "";
            String responseString = requestResponse.response() != null ? requestResponse.response().toString() : "";
            
            List<String> foundTokens = new ArrayList<>();
            
            // Look for JWT patterns
            Pattern jwtPattern = Pattern.compile("(eyJ[A-Za-z0-9_-]+\\\\.eyJ[A-Za-z0-9_-]+\\\\.[A-Za-z0-9_-]*)");
            
            Matcher requestMatcher = jwtPattern.matcher(requestString);
            while (requestMatcher.find()) {
                foundTokens.add("REQUEST: " + requestMatcher.group(1).substring(0, Math.min(50, requestMatcher.group(1).length())) + "...");
            }
            
            Matcher responseMatcher = jwtPattern.matcher(responseString);
            while (responseMatcher.find()) {
                foundTokens.add("RESPONSE: " + responseMatcher.group(1).substring(0, Math.min(50, responseMatcher.group(1).length())) + "...");
            }
            
            if (foundTokens.isEmpty()) {
                return "No JWT tokens detected";
            } else {
                StringBuilder result = new StringBuilder();
                result.append("Found ").append(foundTokens.size()).append(" JWT token(s):\\n");
                for (String token : foundTokens) {
                    result.append("- ").append(token).append("\\n");
                }
                return result.toString();
            }
            
        } catch (Exception e) {
            return "Analysis error: " + e.getMessage();
        }
    }
    
    private void showNotification(String title, String message) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    JOptionPane.showMessageDialog(
                        null,
                        message,
                        title,
                        JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception e) {
                    api.logging().logToError("Error showing notification: " + e.getMessage());
                }
            }
        });
    }
    
    private void showErrorNotification(String title, String message) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    JOptionPane.showMessageDialog(
                        null,
                        message,
                        title,
                        JOptionPane.ERROR_MESSAGE
                    );
                } catch (Exception e) {
                    api.logging().logToError("Error showing error notification: " + e.getMessage());
                }
            }
        });
    }
}
