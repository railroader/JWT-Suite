import burp.api.montoya.MontoyaApi;
import javax.swing.*;

/**
 * Simple main tab highlighter that uses Burp's native highlighting system.
 * Just adds/removes the dot indicator to trigger Burp's default highlighting.
 */
public class MainTabHighlighter {
    private static MontoyaApi api;
    private static JTabbedPane extensionTabbedPane;
    private static boolean isHighlighted = false;
    private static final String ORIGINAL_TAB_NAME = "JWT Manager";
    private static final String HIGHLIGHTED_TAB_NAME = "JWT Manager ●";
    
    /**
     * Initialize the highlighter
     */
    public static void initialize(MontoyaApi burpApi, JTabbedPane tabbedPane) {
        api = burpApi;
        extensionTabbedPane = tabbedPane;
        
        // Add change listener to remove highlight when user clicks on JWT Manager
        if (tabbedPane != null) {
            tabbedPane.addChangeListener(new javax.swing.event.ChangeListener() {
                @Override
                public void stateChanged(javax.swing.event.ChangeEvent e) {
                    removeHighlight();
                }
            });
        }
        
        api.logging().logToOutput("MainTabHighlighter initialized");
    }
    
    /**
     * Highlight the main JWT Manager tab
     */
    public static void highlightMainTab() {
        if (api == null || isHighlighted) {
            return;
        }
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    // Re-register with highlighted name - let Burp handle the color
                    api.userInterface().registerSuiteTab(HIGHLIGHTED_TAB_NAME, extensionTabbedPane);
                    isHighlighted = true;
                    
                    api.logging().logToOutput("JWT Manager main tab highlighted");
                    
                } catch (Exception e) {
                    api.logging().logToError("Error highlighting main tab: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Remove highlight from main tab
     */
    public static void removeHighlight() {
        if (api == null || !isHighlighted) {
            return;
        }
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    // Re-register with original name
                    api.userInterface().registerSuiteTab(ORIGINAL_TAB_NAME, extensionTabbedPane);
                    isHighlighted = false;
                    
                    api.logging().logToOutput("JWT Manager main tab highlight removed");
                    
                } catch (Exception e) {
                    api.logging().logToError("Error removing main tab highlight: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Check if main tab is currently highlighted
     */
    public static boolean isHighlighted() {
        return isHighlighted;
    }
}
