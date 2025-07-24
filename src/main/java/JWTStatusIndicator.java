import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import java.awt.*;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Creates status indicators within JWT Manager tab content to show when new requests arrive.
 * Provides clear visual feedback similar to activity indicators in other tools.
 */
public class JWTStatusIndicator {
    private static MontoyaApi api;
    private static JPanel statusPanel;
    private static JLabel statusLabel;
    private static JLabel activityDot;
    private static Timer fadeTimer;
    private static boolean isActive = false;
    
    // Colors for status indication
    private static final Color ACTIVE_COLOR = new Color(255, 140, 0); // Orange like Burp
    private static final Color INACTIVE_COLOR = new Color(128, 128, 128); // Gray
    private static final Color SUCCESS_COLOR = new Color(76, 175, 80); // Green
    
    /**
     * Initialize the status indicator system
     */
    public static void initialize(MontoyaApi burpApi) {
        api = burpApi;
        createStatusPanel();
        api.logging().logToOutput("JWT Status Indicator initialized");
    }
    
    /**
     * Create the status panel that will be added to tab content
     */
    private static void createStatusPanel() {
        statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        statusPanel.setOpaque(false);
        
        // Activity dot indicator
        activityDot = new JLabel("●");
        activityDot.setFont(new Font("Arial", Font.BOLD, 14));
        activityDot.setForeground(INACTIVE_COLOR);
        
        // Status text
        statusLabel = new JLabel("Ready");
        statusLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        statusLabel.setForeground(ThemeManager.getForegroundColor());
        
        statusPanel.add(activityDot);
        statusPanel.add(statusLabel);
        
        // Apply theme styling
        ThemeManager.styleComponent(statusPanel);
    }
    
    /**
     * Get the status panel to be added to tab content
     */
    public static JPanel getStatusPanel() {
        if (statusPanel == null) {
            createStatusPanel();
        }
        return statusPanel;
    }
    
    /**
     * Show activity when new request is received
     */
    public static void showActivity(String message) {
        if (statusPanel == null) return;
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    // Cancel any existing timer
                    if (fadeTimer != null) {
                        fadeTimer.cancel();
                    }
                    
                    // Set active state
                    activityDot.setForeground(ACTIVE_COLOR);
                    statusLabel.setText(message);
                    statusLabel.setForeground(ACTIVE_COLOR);
                    isActive = true;
                    
                    // Make the dot pulse by changing size
                    pulseDot();
                    
                    // Auto-fade after 5 seconds
                    fadeTimer = new Timer();
                    fadeTimer.schedule(new TimerTask() {
                        @Override
                        public void run() {
                            fadeToReady();
                        }
                    }, 5000);
                    
                    api.logging().logToOutput("JWT Status: " + message);
                    
                } catch (Exception e) {
                    api.logging().logToError("Error showing activity: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Show success status
     */
    public static void showSuccess(String message) {
        if (statusPanel == null) return;
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    activityDot.setForeground(SUCCESS_COLOR);
                    statusLabel.setText(message);
                    statusLabel.setForeground(SUCCESS_COLOR);
                    
                    // Auto-fade after 3 seconds
                    Timer successTimer = new Timer();
                    successTimer.schedule(new TimerTask() {
                        @Override
                        public void run() {
                            fadeToReady();
                        }
                    }, 3000);
                    
                } catch (Exception e) {
                    api.logging().logToError("Error showing success: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Create pulsing effect for the activity dot
     */
    private static void pulseDot() {
        Timer pulseTimer = new Timer();
        pulseTimer.scheduleAtFixedRate(new TimerTask() {
            private boolean large = false;
            private int pulseCount = 0;
            
            @Override
            public void run() {
                if (!isActive || pulseCount >= 10) {
                    this.cancel();
                    return;
                }
                
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        if (large) {
                            activityDot.setFont(new Font("Arial", Font.BOLD, 16));
                        } else {
                            activityDot.setFont(new Font("Arial", Font.BOLD, 12));
                        }
                        large = !large;
                        pulseCount++;
                        statusPanel.repaint();
                    }
                });
            }
        }, 0, 200); // Pulse every 200ms
    }
    
    /**
     * Fade back to ready state
     */
    private static void fadeToReady() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    activityDot.setForeground(INACTIVE_COLOR);
                    activityDot.setFont(new Font("Arial", Font.BOLD, 14));
                    statusLabel.setText("Ready");
                    statusLabel.setForeground(ThemeManager.getForegroundColor());
                    isActive = false;
                    statusPanel.repaint();
                    
                } catch (Exception e) {
                    api.logging().logToError("Error fading to ready: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Show request received notification
     */
    public static void showRequestReceived() {
        showActivity("Request received");
    }
    
    /**
     * Show requests sent to tools
     */
    public static void showRequestsSentToTools() {
        showActivity("Sent to JWT tools");
    }
    
    /**
     * Show JWT analysis in progress
     */
    public static void showAnalysisInProgress() {
        showActivity("Analyzing JWT...");
    }
    
    /**
     * Show analysis complete
     */
    public static void showAnalysisComplete() {
        showSuccess("Analysis complete");
    }
    
    /**
     * Show brute force started
     */
    public static void showBruteForceStarted() {
        showActivity("Brute force started");
    }
    
    /**
     * Show attack started
     */
    public static void showAttackStarted() {
        showActivity("Attack started");
    }
    
    /**
     * Clear all status
     */
    public static void clearStatus() {
        fadeToReady();
    }
    
    /**
     * Check if currently showing activity
     */
    public static boolean isActive() {
        return isActive;
    }
    
    /**
     * Clean up resources for proper extension unloading
     */
    public static void cleanup() {
        // Cancel any running timers
        if (fadeTimer != null) {
            fadeTimer.cancel();
            fadeTimer = null;
        }
        
        // Clear status
        isActive = false;
        
        // Clear UI components
        if (statusLabel != null) {
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("Extension unloaded");
                if (activityDot != null) {
                    activityDot.setForeground(INACTIVE_COLOR);
                }
            });
        }
        
        api.logging().logToOutput("JWTStatusIndicator cleanup completed");
    }
}
