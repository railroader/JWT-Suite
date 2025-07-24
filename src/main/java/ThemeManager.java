import javax.swing.*;
import java.awt.*;

/**
 * Centralized theme management for JWT Manager extension
 * Provides consistent colors and fonts that respect Burp's light/dark theme setting
 * 
 * This class eliminates hardcoded colors and ensures proper contrast
 * and readability in both light and dark themes.
 */
public class ThemeManager {
    
    // Private constructor to prevent instantiation - this is a utility class
    private ThemeManager() {}
    
    /**
     * Get the current background color for main panels
     * @return Color that works in current theme
     */
    public static Color getBackgroundColor() {
        return UIManager.getColor("Panel.background");
    }
    
    /**
     * Get the current foreground color for text
     * @return Color that works in current theme
     */
    public static Color getForegroundColor() {
        return UIManager.getColor("Label.foreground");
    }
    
    /**
     * Get the current background color for text areas and editors
     * @return Color that works in current theme
     */
    public static Color getTextAreaBackgroundColor() {
        return UIManager.getColor("TextArea.background");
    }
    
    /**
     * Get the current foreground color for text areas and editors
     * @return Color that works in current theme
     */
    public static Color getTextAreaForegroundColor() {
        return UIManager.getColor("TextArea.foreground");
    }
    
    /**
     * Get the current selection background color
     * @return Color that works in current theme
     */
    public static Color getSelectionBackgroundColor() {
        return UIManager.getColor("Table.selectionBackground");
    }
    
    /**
     * Get the current selection foreground color
     * @return Color that works in current theme
     */
    public static Color getSelectionForegroundColor() {
        return UIManager.getColor("Table.selectionForeground");
    }
    
    /**
     * Get the current table header background color
     * @return Color that works in current theme
     */
    public static Color getTableHeaderBackgroundColor() {
        return UIManager.getColor("TableHeader.background");
    }
    
    /**
     * Get the current table header foreground color
     * @return Color that works in current theme
     */
    public static Color getTableHeaderForegroundColor() {
        return UIManager.getColor("TableHeader.foreground");
    }
    
    /**
     * Get the current table grid color
     * @return Color that works in current theme
     */
    public static Color getTableGridColor() {
        return UIManager.getColor("Table.gridColor");
    }
    
    /**
     * Get the current border color
     * @return Color that works in current theme
     */
    public static Color getBorderColor() {
        Color gridColor = UIManager.getColor("Table.gridColor");
        if (gridColor != null) {
            return gridColor;
        }
        // Fallback to a computed border color
        Color bg = getBackgroundColor();
        if (bg != null) {
            return bg.darker();
        }
        return Color.GRAY;
    }
    
    /**
     * Get color for disabled/secondary text
     * @return Color that works in current theme
     */
    public static Color getDisabledForegroundColor() {
        return UIManager.getColor("Label.disabledForeground");
    }
    
    /**
     * Get color for success/positive status
     * @return Color that works in current theme
     */
    public static Color getSuccessColor() {
        // Use default foreground color for success to ensure readability
        return getForegroundColor();
    }
    
    /**
     * Get color for error/negative status
     * @return Color that works in current theme
     */
    public static Color getErrorColor() {
        // Use disabled foreground color for errors to provide visual distinction
        // while maintaining theme compatibility
        return getDisabledForegroundColor();
    }
    
    /**
     * Get color for warning/caution status
     * @return Color that works in current theme
     */
    public static Color getWarningColor() {
        return getForegroundColor();
    }
    
    /**
     * Get color for informational status
     * @return Color that works in current theme
     */
    public static Color getInfoColor() {
        return getForegroundColor();
    }
    
    /**
     * Get the default color (same as foreground)
     * @return Color that works in current theme
     */
    public static Color getDefaultColor() {
        return getForegroundColor();
    }
    
    /**
     * Get the default font for the extension
     * @return Font that respects system/theme settings
     */
    public static Font getDefaultFont() {
        Font defaultFont = UIManager.getFont("Label.font");
        if (defaultFont != null) {
            return defaultFont;
        }
        return new Font(Font.SANS_SERIF, Font.PLAIN, 12);
    }
    
    /**
     * Get a monospace font for code/data display
     * @return Monospace font that respects system settings
     */
    public static Font getMonospaceFont() {
        Font textAreaFont = UIManager.getFont("TextArea.font");
        if (textAreaFont != null && textAreaFont.getFamily().toLowerCase().contains("mono")) {
            return textAreaFont;
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }
    
    /**
     * Get a larger font for headers and titles
     * @return Larger font for emphasis
     */
    public static Font getTitleFont() {
        Font defaultFont = getDefaultFont();
        return defaultFont.deriveFont(Font.BOLD, defaultFont.getSize() + 2);
    }
    
    /**
     * Apply consistent theme styling to a JTable
     * @param table Table to style
     */
    public static void styleTable(JTable table) {
        if (table == null) return;
        
        // Table styling
        table.setBackground(getBackgroundColor());
        table.setForeground(getForegroundColor());
        table.setSelectionBackground(getSelectionBackgroundColor());
        table.setSelectionForeground(getSelectionForegroundColor());
        table.setGridColor(getTableGridColor());
        table.setFont(getDefaultFont());
        
        // Header styling
        if (table.getTableHeader() != null) {
            table.getTableHeader().setBackground(getTableHeaderBackgroundColor());
            table.getTableHeader().setForeground(getTableHeaderForegroundColor());
            table.getTableHeader().setFont(getDefaultFont());
        }
        
        // Row height and spacing
        table.setRowHeight(Math.max(table.getRowHeight(), 25));
        table.setShowGrid(true);
        table.setIntercellSpacing(new Dimension(1, 1));
    }
    
    /**
     * Apply consistent theme styling to a JTextArea
     * @param textArea TextArea to style
     */
    public static void styleTextArea(JTextArea textArea) {
        if (textArea == null) return;
        
        textArea.setBackground(getTextAreaBackgroundColor());
        textArea.setForeground(getTextAreaForegroundColor());
        textArea.setCaretColor(getTextAreaForegroundColor());
        textArea.setFont(getDefaultFont());
    }
    
    /**
     * Apply monospace font styling to a JTextArea for code/data display
     * @param textArea TextArea to style
     */
    public static void styleMonospaceTextArea(JTextArea textArea) {
        if (textArea == null) return;
        
        styleTextArea(textArea);
        textArea.setFont(getMonospaceFont());
        textArea.setTabSize(4);
    }
    
    /**
     * Apply consistent theme styling to a JLabel
     * @param label Label to style
     */
    public static void styleLabel(JLabel label) {
        if (label == null) return;
        
        label.setForeground(getForegroundColor());
        label.setFont(getDefaultFont());
    }
    
    /**
     * Apply title styling to a JLabel
     * @param label Label to style as title
     */
    public static void styleTitleLabel(JLabel label) {
        if (label == null) return;
        
        label.setForeground(getForegroundColor());
        label.setFont(getTitleFont());
    }
    
    /**
     * Apply status styling to a JLabel (for status messages)
     * @param label Label to style
     * @param status Status type: "success", "error", "warning", or "normal"
     */
    public static void styleStatusLabel(JLabel label, String status) {
        if (label == null) return;
        
        label.setFont(getDefaultFont());
        
        if ("success".equalsIgnoreCase(status)) {
            label.setForeground(getSuccessColor());
        } else if ("error".equalsIgnoreCase(status)) {
            label.setForeground(getErrorColor());
        } else if ("warning".equalsIgnoreCase(status)) {
            label.setForeground(getWarningColor());
        } else {
            label.setForeground(getForegroundColor());
        }
    }
    
    /**
     * Apply consistent theme styling to a JButton
     * @param button Button to style
     */
    public static void styleButton(JButton button) {
        if (button == null) return;
        
        // Let the button use system defaults for proper theme support
        button.setFont(getDefaultFont());
        // Don't override button colors as they have special system styling
    }
    
    /**
     * Apply consistent theme styling to a JTabbedPane
     * @param tabbedPane TabbedPane to style
     */
    public static void styleTabbedPane(JTabbedPane tabbedPane) {
        if (tabbedPane == null) return;
        
        tabbedPane.setBackground(getBackgroundColor());
        tabbedPane.setForeground(getForegroundColor());
        tabbedPane.setFont(getDefaultFont());
    }
    
    /**
     * Apply generic theme styling to any component
     * @param component Component to style
     */
    public static void styleComponent(Component component) {
        if (component == null) return;
        
        // Handle specific component types
        if (component instanceof JTable) {
            styleTable((JTable) component);
        } else if (component instanceof JTextArea) {
            styleTextArea((JTextArea) component);
        } else if (component instanceof JLabel) {
            styleLabel((JLabel) component);
        } else if (component instanceof JButton) {
            styleButton((JButton) component);
        } else if (component instanceof JScrollPane) {
            styleScrollPane((JScrollPane) component);
        } else if (component instanceof JTabbedPane) {
            styleTabbedPane((JTabbedPane) component);
        } else {
            // Generic component styling
            component.setBackground(getBackgroundColor());
            component.setForeground(getForegroundColor());
            if (component instanceof JComponent) {
                ((JComponent) component).setFont(getDefaultFont());
            }
        }
    }
    
    /**
     * Apply consistent theme styling to a JScrollPane
     * @param scrollPane ScrollPane to style
     */
    public static void styleScrollPane(JScrollPane scrollPane) {
        if (scrollPane == null) return;
        
        scrollPane.getViewport().setBackground(getTextAreaBackgroundColor());
        scrollPane.setBorder(BorderFactory.createLineBorder(getBorderColor()));
    }
    
    /**
     * Create a themed titled border
     * @param title Border title
     * @return TitledBorder with theme-appropriate colors
     */
    public static javax.swing.border.TitledBorder createTitledBorder(String title) {
        javax.swing.border.TitledBorder border = BorderFactory.createTitledBorder(title);
        border.setTitleColor(getForegroundColor());
        border.setTitleFont(getDefaultFont());
        return border;
    }
    
    /**
     * Check if we're currently using a dark theme
     * This is a best-effort detection based on background color brightness
     * @return true if likely using dark theme
     */
    public static boolean isDarkTheme() {
        Color bg = getBackgroundColor();
        if (bg == null) return false;
        
        // Calculate brightness using standard formula
        double brightness = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) / 255.0;
        return brightness < 0.5;
    }
    
    /**
     * Get an appropriate contrast color for the current theme
     * @return Color that provides good contrast
     */
    public static Color getContrastColor() {
        return isDarkTheme() ? Color.WHITE : Color.BLACK;
    }
    
    /**
     * Apply full theme styling to a component and all its children recursively
     * @param component Component to style
     */
    public static void applyThemeRecursively(Container component) {
        if (component == null) return;
        
        // Style the component itself
        if (component instanceof JTable) {
            styleTable((JTable) component);
        } else if (component instanceof JTextArea) {
            styleTextArea((JTextArea) component);
        } else if (component instanceof JLabel) {
            styleLabel((JLabel) component);
        } else if (component instanceof JButton) {
            styleButton((JButton) component);
        } else if (component instanceof JScrollPane) {
            styleScrollPane((JScrollPane) component);
        }
        
        // Apply to all children
        for (Component child : component.getComponents()) {
            if (child instanceof Container) {
                applyThemeRecursively((Container) child);
            }
        }
    }
}
