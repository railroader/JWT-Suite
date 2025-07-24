import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Window for displaying request and response details with native Burp syntax highlighting
 */
public class RequestResponseViewer extends JDialog {
    private APICallData apiCallData;
    private MontoyaApi api;
    private JLabel detailsLabel;
    
    // Native Burp editors for syntax highlighting
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    
    public RequestResponseViewer(JFrame parent, APICallData apiCallData) {
        super(parent, "Request/Response Viewer - #" + apiCallData.getRequestNumber(), true);
        this.apiCallData = apiCallData;
        
        // Get MontoyaApi from the parent frame (assumes it's stored there)
        // Since we can't easily pass API reference, we'll use a workaround
        this.api = JWTInit.getApi(); // Get API from main class
        
        initializeNativeEditors();
        initializeUI();
        loadData();
        
        // Center on parent
        setLocationRelativeTo(parent);
    }
    
    private void initializeNativeEditors() {
        // Initialize native Burp HTTP editors with read-only mode
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
    }
    
    private void initializeUI() {
        setSize(1000, 700);
        setLayout(new BorderLayout());
        
        // Top panel with details
        JPanel detailsPanel = createDetailsPanel();
        
        // Center panel with request/response
        JPanel contentPanel = createContentPanel();
        
        // Bottom panel with buttons
        JPanel buttonPanel = createButtonPanel();
        
        add(detailsPanel, BorderLayout.NORTH);
        add(contentPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Request Details"));
        panel.setPreferredSize(new Dimension(0, 120));
        
        detailsLabel = new JLabel();
        detailsLabel.setVerticalAlignment(SwingConstants.TOP);
        detailsLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        ThemeManager.styleLabel(detailsLabel);
        
        JScrollPane scrollPane = new JScrollPane(detailsLabel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }
    
    private JPanel createContentPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create split pane for request/response
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        splitPane.setContinuousLayout(true);
        splitPane.setOneTouchExpandable(true);
        
        // Request panel with native editor
        JPanel requestPanel = createRequestPanel();
        
        // Response panel with native editor
        JPanel responsePanel = createResponsePanel();
        
        splitPane.setLeftComponent(requestPanel);
        splitPane.setRightComponent(responsePanel);
        
        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }
    
    private JPanel createRequestPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Request"));
        
        // Use native Burp HTTP request editor
        Component requestEditorComponent = requestEditor.uiComponent();
        panel.add(requestEditorComponent, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createResponsePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Response"));
        
        // Use native Burp HTTP response editor
        Component responseEditorComponent = responseEditor.uiComponent();
        panel.add(responseEditorComponent, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout());
        
        JButton copyRequestButton = new JButton("Copy Request");
        JButton copyResponseButton = new JButton("Copy Response");
        JButton closeButton = new JButton("Close");
        
        copyRequestButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyRequestToClipboard();
            }
        });
        
        copyResponseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyResponseToClipboard();
            }
        });
        
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dispose();
            }
        });
        
        panel.add(copyRequestButton);
        panel.add(copyResponseButton);
        panel.add(closeButton);
        
        return panel;
    }
    
    private void loadData() {
        // Set details
        String detailsHtml = "<html>" + 
            apiCallData.getFormattedRequestDetails().replace("\\n", "<br>") + 
            "</html>";
        detailsLabel.setText(detailsHtml);
        
        // Load request data into native editor
        loadRequestData();
        
        // Load response data into native editor
        loadResponseData();
    }
    
    private void loadRequestData() {
        try {
            String requestData = apiCallData.getRequestData();
            if (requestData != null && !requestData.isEmpty()) {
                // Parse the stored request data and create an HttpRequest object
                HttpRequest httpRequest = parseRequestData(requestData);
                if (httpRequest != null) {
                    requestEditor.setRequest(httpRequest);
                } else {
                    // Fallback: set as plain text
                    setEditorFallbackText(requestEditor, requestData);
                }
            } else {
                setEditorFallbackText(requestEditor, "No request data available");
            }
        } catch (Exception e) {
            setEditorFallbackText(requestEditor, "Error loading request data: " + e.getMessage());
        }
    }
    
    private void loadResponseData() {
        try {
            String responseData = apiCallData.getResponseData();
            if (responseData != null && !responseData.isEmpty() && !responseData.startsWith("Response pending")) {
                // Parse the stored response data and create an HttpResponse object
                HttpResponse httpResponse = parseResponseData(responseData);
                if (httpResponse != null) {
                    responseEditor.setResponse(httpResponse);
                } else {
                    // Fallback: set as plain text
                    setEditorFallbackText(responseEditor, responseData);
                }
            } else {
                setEditorFallbackText(responseEditor, "No response data available");
            }
        } catch (Exception e) {
            setEditorFallbackText(responseEditor, "Error loading response data: " + e.getMessage());
        }
    }
    
    private HttpRequest parseRequestData(String requestData) {
        try {
            // Use HttpFormatter to parse the request data back into an HttpRequest
            return HttpFormatter.parseHttpRequest(requestData);
        } catch (Exception e) {
            api.logging().logToError("Failed to parse request data: " + e.getMessage());
            return null;
        }
    }
    
    private HttpResponse parseResponseData(String responseData) {
        try {
            // Use HttpFormatter to parse the response data back into an HttpResponse  
            return HttpFormatter.parseHttpResponse(responseData);
        } catch (Exception e) {
            api.logging().logToError("Failed to parse response data: " + e.getMessage());
            return null;
        }
    }
    
    private void setEditorFallbackText(HttpRequestEditor editor, String text) {
        try {
            // Create a minimal HTTP request with the text as body for display
            HttpRequest fallbackRequest = HttpRequest.httpRequest("GET /fallback HTTP/1.1\r\n\r\n" + text);
            editor.setRequest(fallbackRequest);
        } catch (Exception e) {
            // Last resort: create empty request
            HttpRequest emptyRequest = HttpRequest.httpRequest("GET / HTTP/1.1\r\n\r\n");
            editor.setRequest(emptyRequest);
        }
    }
    
    private void setEditorFallbackText(HttpResponseEditor editor, String text) {
        try {
            // Create a minimal HTTP response with the text as body for display
            HttpResponse fallbackResponse = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + text);
            editor.setResponse(fallbackResponse);
        } catch (Exception e) {
            // Last resort: create empty response
            HttpResponse emptyResponse = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n");
            editor.setResponse(emptyResponse);
        }
    }
    
    private void copyRequestToClipboard() {
        try {
            HttpRequest request = requestEditor.getRequest();
            if (request != null) {
                String requestText = request.toString();
                copyToClipboard(requestText);
            } else {
                showError("No request data to copy");
            }
        } catch (Exception e) {
            showError("Failed to copy request: " + e.getMessage());
        }
    }
    
    private void copyResponseToClipboard() {
        try {
            HttpResponse response = responseEditor.getResponse();
            if (response != null) {
                String responseText = response.toString();
                copyToClipboard(responseText);
            } else {
                showError("No response data to copy");
            }
        } catch (Exception e) {
            showError("Failed to copy response: " + e.getMessage());
        }
    }
    
    private void copyToClipboard(String text) {
        try {
            java.awt.datatransfer.StringSelection stringSelection = 
                new java.awt.datatransfer.StringSelection(text);
            java.awt.datatransfer.Clipboard clipboard = 
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            
            JOptionPane.showMessageDialog(this, "Copied to clipboard!", "Success", 
                JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            showError("Failed to copy to clipboard: " + e.getMessage());
        }
    }
    
    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }
}