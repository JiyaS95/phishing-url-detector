package com.jiya.phishing_detector_api.detector;

import java.util.List;
import java.util.ArrayList;

public class EmailResult {
    private List<String> warnings = new ArrayList<>();
    private int riskScore;
    private String riskLevel;
    private List<String> suspiciousUrls = new ArrayList<>();
    private String error;

    public void addWarning(String warning) { warnings.add(warning); }
    public List<String> getWarnings() { return warnings; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public int getRiskScore() { return riskScore; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public String getRiskLevel() { return riskLevel; }
    public void addSuspiciousUrl(String url) { suspiciousUrls.add(url); }
    public List<String> getSuspiciousUrls() { return suspiciousUrls; }
    public void setError(String error) { this.error = error; }
    public String getError() { return error; }
}
