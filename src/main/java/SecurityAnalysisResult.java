import java.util.*;

/**
 * Contains the results of JWT security analysis including findings and summary
 */
public class SecurityAnalysisResult {
    private List<SecurityFinding> findings;
    private Map<String, Integer> severityCounts;
    
    public SecurityAnalysisResult() {
        this.findings = new ArrayList<>();
        this.severityCounts = new HashMap<>();
        initializeSeverityCounts();
    }
    
    private void initializeSeverityCounts() {
        severityCounts.put("critical", 0);
        severityCounts.put("high", 0);
        severityCounts.put("medium", 0);
        severityCounts.put("low", 0);
        severityCounts.put("info", 0);
    }
    
    public void addFinding(SecurityFinding finding) {
        findings.add(finding);
        String severity = finding.getSeverity().toLowerCase();
        severityCounts.put(severity, severityCounts.getOrDefault(severity, 0) + 1);
    }
    
    public List<SecurityFinding> getFindings() {
        return findings;
    }
    
    public Map<String, Integer> getSeverityCounts() {
        return severityCounts;
    }
    
    public int getTotalFindings() {
        return findings.size();
    }
    
    public int getCriticalCount() {
        return severityCounts.get("critical");
    }
    
    public int getHighCount() {
        return severityCounts.get("high");
    }
    
    public int getMediumCount() {
        return severityCounts.get("medium");
    }
    
    public int getLowCount() {
        return severityCounts.get("low");
    }
    
    public int getInfoCount() {
        return severityCounts.get("info");
    }
    
    public void sortFindingsBySeverity() {
        Collections.sort(findings, new Comparator<SecurityFinding>() {
            public int compare(SecurityFinding f1, SecurityFinding f2) {
                return f2.getSeverityOrder() - f1.getSeverityOrder();
            }
        });
    }
    
    public String generateSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("SECURITY FINDINGS SUMMARY\n");
        summary.append("=========================\n\n");
        
        if (getCriticalCount() > 0) {
            summary.append(getCriticalCount()).append("\tCritical\n");
        }
        if (getHighCount() > 0) {
            summary.append(getHighCount()).append("\tHigh\n");
        }
        if (getMediumCount() > 0) {
            summary.append(getMediumCount()).append("\tMedium\n");
        }
        if (getLowCount() > 0) {
            summary.append(getLowCount()).append("\tLow\n");
        }
        if (getInfoCount() > 0) {
            summary.append(getInfoCount()).append("\tInfo\n");
        }
        
        summary.append("\nTotal: ").append(getTotalFindings()).append(" findings\n\n");
        return summary.toString();
    }
    
    public String generateDetailedReport() {
        StringBuilder report = new StringBuilder();
        report.append("JWT SECURITY ANALYSIS\n");
        report.append("=====================\n\n");
        
        // Add summary first
        report.append(generateSummary());
        
        // Add detailed findings only for categories that have findings
        report.append("DETAILED FINDINGS\n");
        report.append("=================\n\n");
        
        // Group findings by category
        Map<String, List<SecurityFinding>> groupedFindings = new HashMap<>();
        for (SecurityFinding finding : findings) {
            if (!groupedFindings.containsKey(finding.getCategory())) {
                groupedFindings.put(finding.getCategory(), new ArrayList<SecurityFinding>());
            }
            groupedFindings.get(finding.getCategory()).add(finding);
        }
        
        // Only show categories that have findings
        if (groupedFindings.isEmpty()) {
            report.append("✅ No security issues detected. Token appears to follow best practices.\n");
        } else {
            // Sort categories by highest severity in each category
            List<String> sortedCategories = new ArrayList<>(groupedFindings.keySet());
            Collections.sort(sortedCategories, new Comparator<String>() {
                public int compare(String cat1, String cat2) {
                    int maxSeverity1 = getMaxSeverityInCategory(groupedFindings.get(cat1));
                    int maxSeverity2 = getMaxSeverityInCategory(groupedFindings.get(cat2));
                    return maxSeverity2 - maxSeverity1; // Highest severity first
                }
            });
            
            for (String category : sortedCategories) {
                List<SecurityFinding> categoryFindings = groupedFindings.get(category);
                if (!categoryFindings.isEmpty()) {
                    report.append(category).append("\n");
                    
                    // Sort findings within category by severity
                    Collections.sort(categoryFindings, new Comparator<SecurityFinding>() {
                        public int compare(SecurityFinding f1, SecurityFinding f2) {
                            return f2.getSeverityOrder() - f1.getSeverityOrder();
                        }
                    });
                    
                    for (SecurityFinding finding : categoryFindings) {
                        report.append("  ").append(finding.getSeverityIcon()).append(" ").append(finding.getFormattedMessage()).append("\n");
                    }
                    report.append("\n");
                }
            }
        }
        
        return report.toString();
    }
    
    private int getMaxSeverityInCategory(List<SecurityFinding> findings) {
        int maxSeverity = 0;
        for (SecurityFinding finding : findings) {
            maxSeverity = Math.max(maxSeverity, finding.getSeverityOrder());
        }
        return maxSeverity;
    }
}
