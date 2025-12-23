package com.jiya.phishing_detector_api.detector;
import java.util.List;
import java.util.ArrayList;


public class URLResult {
    private String protocol;
    private String domain;
    private String path;
    private List<String> warnings = new ArrayList<>();
    private int riskScore;

    public void setProtocol (String protocol) {
        this.protocol = protocol;
    }
    public String getProtocol() {
        return protocol;
    }

    public void setHost (String domain) {
        this.domain = domain;
    }
    public String getHost() {
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

    public List<String> getWarnings() {
        return warnings;
    }

    //Add warning message to the list
    public void addWarning (String warning) {
        warnings.add(warning);
    }

    public void print() {
        System.out.println("Protocol: "+protocol);
        System.out.println("Domain: "+domain);
        System.out.println("Path: "+path);

        if (warnings.isEmpty()) {
            System.out.println("✅ No warnings detected");
        }
        else {
            System.out.println("Warnings: ");
            for (int i = 0; i < warnings.size(); i++) {
                System.out.println(" - "+warnings.get(i));
            }

            //Show total risk score and the ranking
            System.out.print("Risk Score: "+riskScore+"/100 ");
            if (riskScore > 0 && riskScore <= 20) {
                System.out.println("--> LOW RISK 🟢");
            }
            else if (riskScore > 20 && riskScore <= 50) {
                System.out.println("--> MEDIUM RISK 🟡");
            }
            else if (riskScore > 50) {
                System.out.println("--> HIGH RISK 🔴");
            }
        }
    }
}