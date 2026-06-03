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
    private Set<String> whitelist = new HashSet<>();
    private Set<String> blacklist = new HashSet<>();

    public PhishingService(SafeBrowsingService safeBrowsingService) {
        this.safeBrowsingService = safeBrowsingService;
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
        return EmailChecker.analyze(emailBody, safeBrowsingService);
    }
}
