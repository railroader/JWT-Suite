import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Custom table model for API call data
 */
public class APICallTableModel extends DefaultTableModel {
    private static final String[] COLUMN_NAMES = {
        "#", "Host", "Type", "Status", "Risk", "Found", "Expires", "Actions"
    };
    
    private List<APICallData> apiCalls;
    
    public APICallTableModel() {
        super(COLUMN_NAMES, 0);
        this.apiCalls = new ArrayList<>();
    }
    
    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 7; // Only Actions column is editable (for buttons)
    }
    
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Integer.class; // # column should be treated as integer for proper sorting
        }
        return String.class;
    }
    
    /**
     * Add API call data to the table
     */
    public void addAPICall(APICallData apiCall) {
        apiCalls.add(apiCall);
        addRow(apiCall.toTableRow());
    }
    
    /**
     * Get API call data for a specific row
     */
    public APICallData getAPICallData(int row) {
        if (row >= 0 && row < apiCalls.size()) {
            return apiCalls.get(row);
        }
        return null;
    }
    
    /**
     * Clear all data
     */
    public void clearAll() {
        apiCalls.clear();
        setRowCount(0);
    }
    
    /**
     * Get all API call data
     */
    public List<APICallData> getAllAPICallData() {
        return new ArrayList<>(apiCalls);
    }
    
    /**
     * Remove API call at specific index
     */
    public void removeAPICall(int index) {
        if (index >= 0 && index < apiCalls.size()) {
            apiCalls.remove(index);
            removeRow(index);
        }
    }
    
    /**
     * Update API call data for a specific row
     */
    public void updateAPICall(int row, APICallData updatedApiCall) {
        if (row >= 0 && row < apiCalls.size()) {
            apiCalls.set(row, updatedApiCall);
            // Update the table row data
            Object[] rowData = updatedApiCall.toTableRow();
            for (int col = 0; col < rowData.length && col < getColumnCount(); col++) {
                setValueAt(rowData[col], row, col);
            }
            // Fire table cell update event to refresh the UI
            fireTableRowsUpdated(row, row);
        }
    }
    
    /**
     * Update specific cell in the table and refresh UI
     */
    public void updateTableCell(int row, int column, Object value) {
        System.out.println("[APICallTableModel] updateTableCell called: row=" + row + ", col=" + column + ", value=" + value);
        if (row >= 0 && row < getRowCount() && column >= 0 && column < getColumnCount()) {
            Object oldValue = getValueAt(row, column);
            setValueAt(value, row, column);
            fireTableCellUpdated(row, column);
            System.out.println("[APICallTableModel] Cell updated from '" + oldValue + "' to '" + value + "' and UI refresh event fired");
        } else {
            System.out.println("[APICallTableModel] Invalid cell coordinates: row=" + row + ", col=" + column + ", maxRow=" + (getRowCount()-1) + ", maxCol=" + (getColumnCount()-1));
        }
    }
    
    /**
     * Find row index by API call ID
     */
    public int findRowByAPICallId(int apiCallId) {
        System.out.println("[APICallTableModel] findRowByAPICallId called with ID: " + apiCallId);
        for (int i = 0; i < apiCalls.size(); i++) {
            System.out.println("[APICallTableModel] Checking row " + i + ", ID: " + apiCalls.get(i).getId());
            if (apiCalls.get(i).getId() == apiCallId) {
                System.out.println("[APICallTableModel] Found row " + i + " for API call ID " + apiCallId);
                return i;
            }
        }
        System.out.println("[APICallTableModel] No row found for API call ID " + apiCallId + ", total rows: " + apiCalls.size());
        return -1;
    }
}