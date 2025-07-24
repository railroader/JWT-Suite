import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;

/**
 * TabIconManager provides icons for JWT Manager extension tabs.
 * Creates simple, themed icons that work well in both light and dark modes.
 */
public class TabIconManager {
    
    private static final int ICON_SIZE = 16;
    
    /**
     * Get icon for Session Management tab
     * Shows a circular arrow representing token refresh/session management
     */
    public static Icon getSessionManagementIcon() {
        return createIcon(new IconDrawer() {
            public void draw(Graphics2D g, int size) {
                // Draw circular arrow for refresh/session concept
                g.setStroke(new BasicStroke(2.0f));
                Color color = ThemeManager.getForegroundColor();
                g.setColor(color);
                
                int margin = 2;
                int diameter = size - (margin * 2);
                int centerX = size / 2;
                int centerY = size / 2;
                
                // Draw circle with gap
                g.drawArc(margin, margin, diameter, diameter, 45, 270);
                
                // Draw arrow head
                int arrowSize = 3;
                int arrowX = centerX + diameter / 2 - 1;
                int arrowY = centerY - 2;
                
                int[] xPoints = {arrowX, arrowX - arrowSize, arrowX - arrowSize};
                int[] yPoints = {arrowY, arrowY - arrowSize, arrowY + arrowSize};
                g.fillPolygon(xPoints, yPoints, 3);
            }
        });
    }
    
    /**
     * Get icon for JWT Analysis tab
     * Shows a magnifying glass over document representing analysis
     */
    public static Icon getJWTAnalysisIcon() {
        return createIcon(new IconDrawer() {
            public void draw(Graphics2D g, int size) {
                Color color = ThemeManager.getForegroundColor();
                g.setColor(color);
                g.setStroke(new BasicStroke(1.5f));
                
                // Draw document/paper
                int docWidth = 8;
                int docHeight = 10;
                int docX = 2;
                int docY = 3;
                g.drawRect(docX, docY, docWidth, docHeight);
                
                // Draw lines on document
                g.setStroke(new BasicStroke(1.0f));
                g.drawLine(docX + 1, docY + 2, docX + docWidth - 1, docY + 2);
                g.drawLine(docX + 1, docY + 4, docX + docWidth - 1, docY + 4);
                g.drawLine(docX + 1, docY + 6, docX + docWidth - 2, docY + 6);
                
                // Draw magnifying glass
                g.setStroke(new BasicStroke(1.5f));
                int glassSize = 4;
                int glassX = size - glassSize - 3;
                int glassY = size - glassSize - 3;
                g.drawOval(glassX, glassY, glassSize, glassSize);
                
                // Draw handle
                g.drawLine(glassX + glassSize, glassY + glassSize, 
                          glassX + glassSize + 2, glassY + glassSize + 2);
            }
        });
    }
    
    /**
     * Get icon for Attack Tools tab
     * Shows a shield with an exclamation mark representing security testing
     */
    public static Icon getAttackToolsIcon() {
        return createIcon(new IconDrawer() {
            public void draw(Graphics2D g, int size) {
                Color color = ThemeManager.getErrorColor();
                g.setColor(color);
                g.setStroke(new BasicStroke(1.5f));
                
                // Draw shield shape
                int centerX = size / 2;
                int margin = 2;
                int width = size - (margin * 2);
                int height = size - margin;
                
                int[] xPoints = {
                    centerX, 
                    margin + width, 
                    margin + width, 
                    centerX + 2,
                    centerX,
                    centerX - 2,
                    margin,
                    margin
                };
                int[] yPoints = {
                    margin,
                    margin + 2,
                    margin + height / 2,
                    height - margin,
                    height,
                    height - margin,
                    margin + height / 2,
                    margin + 2
                };
                
                g.drawPolygon(xPoints, yPoints, 8);
                
                // Draw exclamation mark inside shield
                g.setStroke(new BasicStroke(2.0f));
                g.drawLine(centerX, margin + 3, centerX, margin + 7);
                g.fillOval(centerX - 1, margin + 9, 2, 2);
            }
        });
    }
    
    /**
     * Get icon for Brute Force tab
     * Shows a key representing key cracking/brute force
     */
    public static Icon getBruteForceIcon() {
        return createIcon(new IconDrawer() {
            public void draw(Graphics2D g, int size) {
                Color color = ThemeManager.getForegroundColor();
                g.setColor(color);
                g.setStroke(new BasicStroke(1.5f));
                
                // Draw key shaft
                int keyLength = size - 6;
                int keyY = size / 2;
                g.drawLine(3, keyY, 3 + keyLength, keyY);
                
                // Draw key head (circle)
                int headSize = 5;
                int headX = 2;
                int headY = keyY - headSize / 2;
                g.drawOval(headX, headY, headSize, headSize);
                
                // Draw key teeth
                g.setStroke(new BasicStroke(1.0f));
                int teethX = 3 + keyLength;
                g.drawLine(teethX, keyY, teethX, keyY - 2);
                g.drawLine(teethX, keyY, teethX, keyY + 2);
                g.drawLine(teethX - 2, keyY, teethX - 2, keyY + 1);
            }
        });
    }
    

    
    /**
     * Create an icon using the provided drawing function
     */
    private static Icon createIcon(IconDrawer drawer) {
        BufferedImage image = new BufferedImage(ICON_SIZE, ICON_SIZE, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        
        // Enable anti-aliasing for smooth icons
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        
        // Draw the icon
        drawer.draw(g, ICON_SIZE);
        
        g.dispose();
        return new ImageIcon(image);
    }
    
    /**
     * Abstract class for drawing icons
     */
    private static abstract class IconDrawer {
        public abstract void draw(Graphics2D g, int size);
    }
}
