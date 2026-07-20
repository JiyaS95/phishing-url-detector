package com.jiya.phishing_detector_api.service;

import com.jiya.phishing_detector_api.detector.URLChecker;
import com.jiya.phishing_detector_api.detector.URLResult;
import com.jiya.phishing_detector_api.detector.EmailChecker;
import com.jiya.phishing_detector_api.detector.EmailResult;
import com.jiya.phishing_detector_api.model.User;
import org.springframework.stereotype.Service;

@Service
public class PhishingService {

    private final SafeBrowsingService safeBrowsingService;
    private final GeminiService geminiService;
    private final ScanHistoryService scanHistoryService;
    private final DomainListService domainListService;

    public PhishingService(SafeBrowsingService safeBrowsingService,
                           GeminiService geminiService,
                           ScanHistoryService scanHistoryService,
                           DomainListService domainListService) {
        this.safeBrowsingService = safeBrowsingService;
        this.geminiService = geminiService;
        this.scanHistoryService = scanHistoryService;
        this.domainListService = domainListService;
    }

    public URLResult analyze(String url, User user) {
        // Use database whitelist/blacklist
        URLResult result = URLChecker.analyze(url, domainListService.getWhitelist(), domainListService.getBlacklist());

        if (safeBrowsingService.isMalicious(url)) {
            result.addWarning("Flagged by Google Safe Browsing");
            result.setRiskScore(Math.min(result.getRiskScore() + 50, 100));
            result.setRiskLevel("HIGH");
        }

        // Add Gemini AI analysis for URLs
        String aiAnalysis = geminiService.analyzeUrl(url, result);
        if (aiAnalysis != null) {
            result.setAiAnalysis(aiAnalysis);
        }

        scanHistoryService.saveScan(user, "URL", url, result.getRiskLevel(), result.getRiskScore());
        return result;
    }

    public URLResult analyze(String url) {
        return analyze(url, null);
    }

    public EmailResult analyzeEmail(String emailBody, User user) {
        EmailResult result = EmailChecker.analyze(emailBody, safeBrowsingService);
        String aiAnalysis = geminiService.analyzeEmail(emailBody);
        if (aiAnalysis != null) {
            result.setAiAnalysis(aiAnalysis);
        }
        scanHistoryService.saveScan(user, "EMAIL", emailBody, result.getRiskLevel(), result.getRiskScore());
        return result;
    }

    public EmailResult analyzeEmail(String emailBody) {
        return analyzeEmail(emailBody, null);
    }
}
