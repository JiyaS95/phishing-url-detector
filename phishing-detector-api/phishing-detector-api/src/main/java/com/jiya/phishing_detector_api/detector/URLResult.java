package com.jiya.phishing_detector_api.detector;
import java.util.List;
import java.util.ArrayList;


public class URLResult {
    private String protocol;
    private String domain;
    private String path;
    private List<String> warnings = new ArrayList<>();
    private int riskScore;
    private String error;

    public void setProtocol (String protocol) {
        this.protocol = protocol;
    }
    public String getProtocol() {
        return protocol;
    }

    public void setDomain (String domain) {
        this.domain = domain;
    }
    public String getDomain() {
        return domain;
    }

    public void setPath (String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public void setRiskScore (int riskScore) {
        this.riskScore = riskScore;
    }
    public int getRiskScore() {
        return riskScore;
    }

    public void setError(String error){
        this.error = error;
    }
    public String getError() {
        return error;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    //Add warning message to the list
    public void addWarning (String warning) {
        warnings.add(warning);
    }

    
}