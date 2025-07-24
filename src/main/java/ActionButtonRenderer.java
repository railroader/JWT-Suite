import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

/**
 * Custom button renderer for table action columns with theme support
 */
public class ActionButtonRenderer extends JButton implements TableCellRenderer {
    
    public ActionButtonRenderer() {
        setOpaque(true);
        // Use theme-aware colors instead of hardcoded values
        setBackground(ThemeManager.getSelectionBackgroundColor());
        setForeground(ThemeManager.getSelectionForegroundColor());
        setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        ThemeManager.styleButton(this);
    }
    
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column) {
        setText((value == null) ? "View" : value.toString());
        
        // Update colors each time to handle theme changes
        setBackground(ThemeManager.getSelectionBackgroundColor());
        setForeground(ThemeManager.getSelectionForegroundColor());
        
        return this;
    }
}