import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import java.awt.*;

/**
 * TabHighlightManager handles highlighting of JWT Manager tab when new requests are received.
 * Provides visual feedback similar to Burp's native tabs (Repeater, Intruder, etc.)
 */
public class TabHighlightManager {
    private static MontoyaApi api;
    private static JTabbedPane mainTabbedPane;
    private static boolean isHighlighted = false;
    private static final Color HIGHLIGHT_COLOR = new Color(255, 165, 0); // Orange highlight
    private static String originalTabTitle = "JWT Manager";
    
    /**
     * Initialize the highlight manager with the main tabbed pane
     */
    public static void initialize(MontoyaApi burpApi, JTabbedPane tabbedPane) {
        api = burpApi;
        mainTabbedPane = tabbedPane;
    }
    
    /**
     * Highlight the JWT Manager tab to indicate new content
     * Called when a request is sent to JWT Manager from context menu
     */
    public static void highlightTab() {
        if (api == null || isHighlighted) {
            return; // Already highlighted or not initialized
        }
        
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    // Get the JWT Manager tab index in Burp's main tab bar
                    // Since we can't directly access Burp's main tabs, we'll use the extension tab title
                    Component extensionTab = findJWTManagerTab();
                    if (extensionTab != null) {
                        highlightExtensionTab(extensionTab);
                        isHighlighted = true;
                        
                        api.logging().logToOutput("JWT Manager tab highlighted - new request received");
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error highlighting JWT Manager tab: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Remove highlight from the JWT Manager tab
     * Called when user clicks on the JWT Manager tab
     */
    public static void removeHighlight() {
        if (api == null || !isHighlighted) {
            return; // Not highlighted or not initialized
        }
        
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    Component extensionTab = findJWTManagerTab();
                    if (extensionTab != null) {
                        removeExtensionTabHighlight(extensionTab);
                        isHighlighted = false;
                        
                        api.logging().logToOutput("JWT Manager tab highlight removed");
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error removing JWT Manager tab highlight: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Check if the tab is currently highlighted
     */
    public static boolean isTabHighlighted() {
        return isHighlighted;
    }
    
    /**
     * Find the JWT Manager tab component in Burp's interface
     */
    private static Component findJWTManagerTab() {
        // This is a simplified approach - in practice, Burp's tab highlighting
        // is handled internally and we have limited access to modify it directly
        
        // For our internal tabbed pane, we can highlight our own tabs
        if (mainTabbedPane != null) {
            return mainTabbedPane;
        }
        
        return null;
    }
    
    /**
     * Apply highlight styling to the extension tab
     */
    private static void highlightExtensionTab(Component tab) {
        if (tab instanceof JTabbedPane) {
            JTabbedPane tabbedPane = (JTabbedPane) tab;
            
            // Highlight all tabs within JWT Manager to indicate activity
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                String originalTitle = tabbedPane.getTitleAt(i);
                if (!originalTitle.contains(" ●")) {
                    tabbedPane.setTitleAt(i, originalTitle + " ●");
                    tabbedPane.setForegroundAt(i, HIGHLIGHT_COLOR);
                }
            }
        }
    }
    
    /**
     * Remove highlight styling from the extension tab
     */
    private static void removeExtensionTabHighlight(Component tab) {
        if (tab instanceof JTabbedPane) {
            JTabbedPane tabbedPane = (JTabbedPane) tab;
            
            // Remove highlight from all tabs within JWT Manager
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                String title = tabbedPane.getTitleAt(i);
                if (title.contains(" ●")) {
                    String cleanTitle = title.replace(" ●", "");
                    tabbedPane.setTitleAt(i, cleanTitle);
                    tabbedPane.setForegroundAt(i, ThemeManager.getForegroundColor());
                }
            }
        }
    }
    
    /**
     * Add change listener to detect when user switches to JWT Manager tab
     */
    public static void addTabChangeListener(JTabbedPane tabbedPane) {
        tabbedPane.addChangeListener(new javax.swing.event.ChangeListener() {
            @Override
            public void stateChanged(javax.swing.event.ChangeEvent e) {
                // Remove highlight when user switches to any JWT Manager tab
                if (isHighlighted) {
                    removeHighlight();
                }
            }
        });
    }
    
    /**
     * Highlight specific sub-tab within JWT Manager
     */
    public static void highlightSubTab(String tabName) {
        if (mainTabbedPane == null) return;
        
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    for (int i = 0; i < mainTabbedPane.getTabCount(); i++) {
                        String title = mainTabbedPane.getTitleAt(i);
                        if (title.equals(tabName) && !title.contains(" ●")) {
                            mainTabbedPane.setTitleAt(i, title + " ●");
                            mainTabbedPane.setForegroundAt(i, HIGHLIGHT_COLOR);
                            break;
                        }
                    }
                    
                    // Also highlight the main tab
                    highlightTab();
                    
                } catch (Exception e) {
                    api.logging().logToError("Error highlighting sub-tab " + tabName + ": " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Remove highlight from specific sub-tab
     */
    public static void removeSubTabHighlight(String tabName) {
        if (mainTabbedPane == null) return;
        
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    for (int i = 0; i < mainTabbedPane.getTabCount(); i++) {
                        String title = mainTabbedPane.getTitleAt(i);
                        if (title.equals(tabName + " ●")) {
                            mainTabbedPane.setTitleAt(i, tabName);
                            mainTabbedPane.setForegroundAt(i, ThemeManager.getForegroundColor());
                            break;
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error removing sub-tab highlight " + tabName + ": " + e.getMessage());
                }
            }
        });
    }
}
