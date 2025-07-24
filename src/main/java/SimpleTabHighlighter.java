import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import java.awt.*;

/**
 * Simple and reliable tab highlighting for JWT Manager extension.
 * Highlights internal tabs when new requests are received.
 */
public class SimpleTabHighlighter {
    private static MontoyaApi api;
    private static JTabbedPane extensionTabbedPane;
    private static final Color HIGHLIGHT_COLOR = new Color(255, 165, 0); // Orange
    
    /**
     * Initialize the highlighter with the extension's tabbed pane
     */
    public static void initialize(MontoyaApi burpApi, JTabbedPane tabbedPane) {
        api = burpApi;
        extensionTabbedPane = tabbedPane;
        
        // Add change listener to remove highlights when tabs are clicked
        if (tabbedPane != null) {
            tabbedPane.addChangeListener(new javax.swing.event.ChangeListener() {
                @Override
                public void stateChanged(javax.swing.event.ChangeEvent e) {
                    clearHighlightOnSelectedTab();
                }
            });
        }
        
        api.logging().logToOutput("SimpleTabHighlighter initialized");
    }
    
    /**
     * Highlight a specific tab by name
     */
    public static void highlightTab(String tabName) {
        if (extensionTabbedPane == null) {
            api.logging().logToError("TabHighlighter: extensionTabbedPane is null");
            return;
        }
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    for (int i = 0; i < extensionTabbedPane.getTabCount(); i++) {
                        String currentTitle = extensionTabbedPane.getTitleAt(i);
                        
                        // Check if this is the tab we want to highlight
                        if (currentTitle.equals(tabName)) {
                            // Add highlight indicator if not already present
                            if (!currentTitle.contains(" ●")) {
                                extensionTabbedPane.setTitleAt(i, currentTitle + " ●");
                                extensionTabbedPane.setForegroundAt(i, HIGHLIGHT_COLOR);
                                
                                api.logging().logToOutput("Highlighted tab: " + tabName);
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error highlighting tab " + tabName + ": " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Remove highlight from a specific tab
     */
    public static void removeHighlight(String tabName) {
        if (extensionTabbedPane == null) return;
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    for (int i = 0; i < extensionTabbedPane.getTabCount(); i++) {
                        String currentTitle = extensionTabbedPane.getTitleAt(i);
                        
                        // Check if this is a highlighted version of the tab
                        if (currentTitle.equals(tabName + " ●")) {
                            extensionTabbedPane.setTitleAt(i, tabName);
                            extensionTabbedPane.setForegroundAt(i, ThemeManager.getForegroundColor());
                            
                            api.logging().logToOutput("Removed highlight from tab: " + tabName);
                            break;
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error removing highlight from tab " + tabName + ": " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Clear highlight from currently selected tab
     */
    private static void clearHighlightOnSelectedTab() {
        if (extensionTabbedPane == null) return;
        
        try {
            int selectedIndex = extensionTabbedPane.getSelectedIndex();
            if (selectedIndex >= 0) {
                String selectedTitle = extensionTabbedPane.getTitleAt(selectedIndex);
                
                // If the selected tab is highlighted, remove the highlight
                if (selectedTitle.contains(" ●")) {
                    String cleanTitle = selectedTitle.replace(" ●", "");
                    extensionTabbedPane.setTitleAt(selectedIndex, cleanTitle);
                    extensionTabbedPane.setForegroundAt(selectedIndex, ThemeManager.getForegroundColor());
                    
                    api.logging().logToOutput("Auto-removed highlight from selected tab: " + cleanTitle);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error clearing highlight on selected tab: " + e.getMessage());
        }
    }
    
    /**
     * Remove all highlights from all tabs
     */
    public static void clearAllHighlights() {
        if (extensionTabbedPane == null) return;
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    for (int i = 0; i < extensionTabbedPane.getTabCount(); i++) {
                        String currentTitle = extensionTabbedPane.getTitleAt(i);
                        
                        if (currentTitle.contains(" ●")) {
                            String cleanTitle = currentTitle.replace(" ●", "");
                            extensionTabbedPane.setTitleAt(i, cleanTitle);
                            extensionTabbedPane.setForegroundAt(i, ThemeManager.getForegroundColor());
                        }
                    }
                    
                    api.logging().logToOutput("Cleared all tab highlights");
                } catch (Exception e) {
                    api.logging().logToError("Error clearing all highlights: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Highlight the JWT Analysis tab specifically
     */
    public static void highlightJWTAnalysis() {
        highlightTab("JWT Analysis");
    }
    
    /**
     * Highlight the Attack Tools tab specifically  
     */
    public static void highlightAttackTools() {
        highlightTab("Attack Tools");
    }
    
    /**
     * Highlight the Brute Force tab specifically
     */
    public static void highlightBruteForce() {
        highlightTab("Brute Force");
    }
}
