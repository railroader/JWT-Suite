import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.menu.MenuItem;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.WebSocketMessageEditor;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class JWTInit implements BurpExtension {
    private static MontoyaApi api;
    private SessionManagement sessionManagement;
    private JWTTools jwtTools;
    private AttackTools attackTools;
    private BruteForce bruteForce;
    private JWTTokenEditor tokenEditor;
    private JWTContextMenuProvider contextMenuProvider;
    private JWTHighlightRemover highlightRemover;

    @Override
    public void initialize(MontoyaApi api) {
        JWTInit.api = api;
        api.extension().setName("JWT Suite");
        
        // Initialize components
        sessionManagement = new SessionManagement(api);
        jwtTools = new JWTTools(api);
        attackTools = new AttackTools(api);
        bruteForce = new BruteForce(api);
        tokenEditor = new JWTTokenEditor(api);
        highlightRemover = new JWTHighlightRemover(api);
        
        // Set up cross-component communication
        jwtTools.setTokenEditor(tokenEditor);
        
        // Create UI with theme support
        SwingUtilities.invokeLater(() -> {
            createUI();
        });
        
        // Register HTTP handler for detecting 401 responses
        api.http().registerHttpHandler(sessionManagement);
        
        // Register HTTP handler for removing JWT highlighting
        api.http().registerHttpHandler(highlightRemover);
        
        // Register context menu provider for right-click functionality
        contextMenuProvider = new JWTContextMenuProvider(api, jwtTools, bruteForce, attackTools);
        api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);
        
        // Register unloading handler for proper cleanup
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                api.logging().logToOutput("JWT Suite extension unloading...");
                
                try {
                    // Stop any running brute force threads
                    if (bruteForce != null) {
                        bruteForce.stopAllThreads();
                        api.logging().logToOutput("Stopped brute force threads");
                    }
                    
                    // Clean up session management resources
                    if (sessionManagement != null) {
                        sessionManagement.cleanup();
                        api.logging().logToOutput("Cleaned up session management");
                    }
                    
                    // Clean up attack tools resources
                    if (attackTools != null) {
                        attackTools.cleanup();
                        api.logging().logToOutput("Cleaned up attack tools");
                    }
                    
                    // Clear status indicator
                    if (JWTStatusIndicator.getStatusPanel() != null) {
                        JWTStatusIndicator.cleanup();
                        api.logging().logToOutput("Cleaned up status indicator");
                    }
                    
                    // Clear any cached data in JWT tools
                    if (jwtTools != null) {
                        jwtTools.cleanup();
                        api.logging().logToOutput("Cleaned up JWT tools");
                    }
                    
                    // Clear token editor resources
                    if (tokenEditor != null) {
                        tokenEditor.cleanup();
                        api.logging().logToOutput("Cleaned up token editor");
                    }
                    
                    api.logging().logToOutput("JWT Suite extension unloaded successfully");
                } catch (Exception e) {
                    api.logging().logToError("Error during extension unload: " + e.getMessage());
                    e.printStackTrace(api.logging().error());
                }
            }
        });
        
        api.logging().logToOutput("JWT Suite extension initialized with context menu support and JWT highlight removal");
    }
    
    private void createUI() {
        // Initialize status indicator
        JWTStatusIndicator.initialize(api);
        
        // Create a main panel to hold status indicator and tabs
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Add status indicator at the top
        JPanel statusContainer = new JPanel(new BorderLayout());
        statusContainer.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        statusContainer.add(JWTStatusIndicator.getStatusPanel(), BorderLayout.WEST);
        
        // Add separator line
        JSeparator separator = new JSeparator();
        statusContainer.add(separator, BorderLayout.SOUTH);
        
        mainPanel.add(statusContainer, BorderLayout.NORTH);
        
        // Create a tabbed pane for the extension
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Apply theme styling to the tabbed pane
        ThemeManager.styleComponent(tabbedPane);
        
        // Create tabs for each component with appropriate icons
        tabbedPane.addTab("Session Management", TabIconManager.getSessionManagementIcon(), sessionManagement.getUI());
        tabbedPane.addTab("JWT Analysis", TabIconManager.getJWTAnalysisIcon(), jwtTools.getUI());
        tabbedPane.addTab("Attack Tools", TabIconManager.getAttackToolsIcon(), attackTools.getUI());
        tabbedPane.addTab("Brute Force", TabIconManager.getBruteForceIcon(), bruteForce.getUI());
        tabbedPane.addTab("Token Editor", TabIconManager.getJWTAnalysisIcon(), tokenEditor.getUI());
        

        
        // Set tab tooltips for better user experience
        tabbedPane.setToolTipTextAt(0, "Manage JWT sessions and automatic token refresh");
        tabbedPane.setToolTipTextAt(1, "Analyze and decode JWT tokens from requests");
        tabbedPane.setToolTipTextAt(2, "Perform JWT-specific security attacks");
        tabbedPane.setToolTipTextAt(3, "Brute force JWT signing keys using wordlists");
        tabbedPane.setToolTipTextAt(4, "Interactive JWT token editor for creating and modifying tokens");

        
        // Add tabbed pane to main panel
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Add the main panel to Burp's UI
        api.userInterface().registerSuiteTab("JWT Suite", mainPanel);
    }
    
    public static MontoyaApi getApi() {
        return api;
    }
    

}
