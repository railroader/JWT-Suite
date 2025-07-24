import javax.swing.*;
import java.awt.*;

/**
 * Custom button editor for table action columns with theme support
 */
public class ActionButtonEditor extends DefaultCellEditor {
    
    protected JButton button;
    private String label;
    private boolean isPushed;
    private int currentRow;
    private APICallTableModel tableModel;
    
    public ActionButtonEditor(JCheckBox checkBox, APICallTableModel tableModel) {
        super(checkBox);
        this.tableModel = tableModel;
        
        button = new JButton();
        button.setOpaque(true);
        button.setBackground(ThemeManager.getSelectionBackgroundColor());
        button.setForeground(ThemeManager.getSelectionForegroundColor());
        ThemeManager.styleButton(button);
        button.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        button.addActionListener(e -> fireEditingStopped());
    }
    
    @Override
    public Component getTableCellEditorComponent(JTable table, Object value,
            boolean isSelected, int row, int column) {
        label = (value == null) ? "View" : value.toString();
        button.setText(label);
        isPushed = true;
        currentRow = table.convertRowIndexToModel(row); // Convert view row to model row for sorting
        
        // Update colors to handle theme changes
        button.setBackground(ThemeManager.getSelectionBackgroundColor());
        button.setForeground(ThemeManager.getSelectionForegroundColor());
        
        return button;
    }
    
    @Override
    public Object getCellEditorValue() {
        if (isPushed) {
            // Handle view action
            APICallData apiCallData = tableModel.getAPICallData(currentRow);
            if (apiCallData != null) {
                // Open request/response viewer
                SwingUtilities.invokeLater(() -> {
                    RequestResponseViewer viewer = new RequestResponseViewer(
                        (JFrame) SwingUtilities.getWindowAncestor(button), 
                        apiCallData
                    );
                    viewer.setVisible(true);
                });
            }
        }
        isPushed = false;
        return label;
    }
    
    @Override
    public boolean stopCellEditing() {
        isPushed = false;
        return super.stopCellEditing();
    }
    
    @Override
    protected void fireEditingStopped() {
        super.fireEditingStopped();
    }
}