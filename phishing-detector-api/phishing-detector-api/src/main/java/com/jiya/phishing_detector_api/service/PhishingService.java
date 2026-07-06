package com.jiya.phishing_detector_api.service;

import com.jiya.phishing_detector_api.detector.URLChecker;
import com.jiya.phishing_detector_api.detector.URLResult;
import com.jiya.phishing_detector_api.detector.EmailChecker;
import com.jiya.phishing_detector_api.detector.EmailResult;
import com.jiya.phishing_detector_api.model.User;
import org.springframework.stereotype.Service;
import java.util.Set;
import java.util.HashSet;

@Service
public class PhishingService {

    private final SafeBrowsingService safeBrowsingService;
    private final GeminiService geminiService;
    private final ScanHistoryService scanHistoryService;
    private Set<String> whitelist = new HashSet<>();
    private Set<String> blacklist = new HashSet<>();

    public PhishingService(SafeBrowsingService safeBrowsingService,
                           GeminiService geminiService,
                           ScanHistoryService scanHistoryService) {
        this.safeBrowsingService = safeBrowsingService;
        this.geminiService = geminiService;
        this.scanHistoryService = scanHistoryService;
        whitelist.add("google.com");
        whitelist.add("github.com");
        whitelist.add("walmart.com");
        whitelist.add("amazon.com");
        blacklist.add("phishing.com");
        blacklist.add("badsite.com");
    }

    public URLResult analyze(String url, User user) {
        URLResult result = URLChecker.analyze(url, whitelist, blacklist);
        if (safeBrowsingService.isMalicious(url)) {
            result.addWarning("Flagged by Google Safe Browsing");
            result.setRiskScore(Math.min(result.getRiskScore() + 50, 100));
            result.setRiskLevel("HIGH");
        }
        // Save to history if logged in
        scanHistoryService.saveScan(user, "URL", url, result.getRiskLevel(), result.getRiskScore());
        return result;
    }

    // Keep old method for backward compatibility
    public URLResult analyze(String url) {
        return analyze(url, null);
    }

    public EmailResult analyzeEmail(String emailBody, User user) {
        EmailResult result = EmailChecker.analyze(emailBody, safeBrowsingService);
        String aiAnalysis = geminiService.analyzeEmail(emailBody);
        if (aiAnalysis != null) {
            result.setAiAnalysis(aiAnalysis);
        }
        // Save to history if logged in
        scanHistoryService.saveScan(user, "EMAIL", emailBody, result.getRiskLevel(), result.getRiskScore());
        return result;
    }

    public EmailResult analyzeEmail(String emailBody) {
        return analyzeEmail(emailBody, null);
    }
}
