package com.jiya.phishing_detector_api.service;

import com.jiya.phishing_detector_api.detector.URLChecker;
import com.jiya.phishing_detector_api.detector.URLResult;
import com.jiya.phishing_detector_api.detector.EmailChecker;
import com.jiya.phishing_detector_api.detector.EmailResult;
import org.springframework.stereotype.Service;
import java.util.Set;
import java.util.HashSet;

@Service
public class PhishingService {

    private final SafeBrowsingService safeBrowsingService;
    private final GeminiService geminiService;
    private Set<String> whitelist = new HashSet<>();
    private Set<String> blacklist = new HashSet<>();

    public PhishingService(SafeBrowsingService safeBrowsingService, GeminiService geminiService) {
        this.safeBrowsingService = safeBrowsingService;
        this.geminiService = geminiService;
        whitelist.add("google.com");
        whitelist.add("github.com");
        whitelist.add("walmart.com");
        whitelist.add("amazon.com");
        blacklist.add("phishing.com");
        blacklist.add("badsite.com");
    }

    public URLResult analyze(String url) {
        URLResult result = URLChecker.analyze(url, whitelist, blacklist);
        if (safeBrowsingService.isMalicious(url)) {
            result.addWarning("Flagged by Google Safe Browsing");
            result.setRiskScore(Math.min(result.getRiskScore() + 50, 100));
            result.setRiskLevel("HIGH");
        }
        return result;
    }

    public EmailResult analyzeEmail(String emailBody) {
        EmailResult result = EmailChecker.analyze(emailBody, safeBrowsingService);

        String aiAnalysis = geminiService.analyzeEmail(emailBody);
        if (aiAnalysis != null) {
            result.setAiAnalysis(aiAnalysis);

            String aiUpper = aiAnalysis.toUpperCase();
            if (aiUpper.startsWith("LEGITIMATE")) {
                result.setRiskScore(Math.min(result.getRiskScore(), 15));
                result.setRiskLevel("LOW");
            } else if (aiUpper.startsWith("SUSPICIOUS")) {
                if (result.getRiskScore() < 16) {
                    result.setRiskScore(30);
                    result.setRiskLevel("MEDIUM");
                }
            } else if (aiUpper.startsWith("PHISHING") || aiUpper.startsWith("SCAM")) {
                if (result.getRiskScore() < 46) {
                    result.setRiskScore(70);
                }
                result.setRiskLevel("HIGH");
            }
        }
        return result;
    }
}
