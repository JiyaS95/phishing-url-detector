package com.jiya.phishing_detector_api.service;

import com.jiya.phishing_detector_api.detector.URLChecker;
import com.jiya.phishing_detector_api.detector.URLResult;
import com.jiya.phishing_detector_api.detector.EmailChecker;
import com.jiya.phishing_detector_api.detector.EmailResult;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.repository.ScamReportRepository;
import org.springframework.stereotype.Service;

@Service
public class PhishingService {

    private final SafeBrowsingService safeBrowsingService;
    private final GeminiService geminiService;
    private final ScanHistoryService scanHistoryService;
    private final DomainListService domainListService;
    private final WhoisService whoisService;
    private final ScamReportRepository scamReportRepository;

    public PhishingService(SafeBrowsingService safeBrowsingService,
                           GeminiService geminiService,
                           ScanHistoryService scanHistoryService,
                           DomainListService domainListService,
                           WhoisService whoisService,
                           ScamReportRepository scamReportRepository) {
        this.safeBrowsingService = safeBrowsingService;
        this.geminiService = geminiService;
        this.scanHistoryService = scanHistoryService;
        this.domainListService = domainListService;
        this.whoisService = whoisService;
        this.scamReportRepository = scamReportRepository;
    }

    public URLResult analyze(String url, User user) {
        URLResult result = URLChecker.analyze(url, domainListService.getWhitelist(), domainListService.getBlacklist());

        if (safeBrowsingService.isMalicious(url)) {
            result.addWarning("🚨 Flagged by Google Safe Browsing");
            result.setRiskScore(Math.min(result.getRiskScore() + 50, 100));
            result.setRiskLevel("HIGH 🔴");
        }

        // WHOIS domain age check
        try {
            java.net.URL urlObj = new java.net.URL(url);
            String domain = urlObj.getHost();
            WhoisService.WhoisResult whois = whoisService.checkDomain(domain);
            if (whois != null) {
                result.setDomainAge(whois.getCreatedDate());
                if (whois.getAgeInDays() < 30) {
                    result.addWarning("⚠️ Domain registered less than 30 days ago (very new — high risk)");
                    result.setRiskScore(Math.min(result.getRiskScore() + 40, 100));
                } else if (whois.getAgeInDays() < 180) {
                    result.addWarning("⚠️ Domain registered less than 6 months ago (relatively new)");
                    result.setRiskScore(Math.min(result.getRiskScore() + 20, 100));
                }
            }
        } catch (Exception ignored) {}

        // Check community reports
        scamReportRepository.findByUrlOrEmailValue(url).ifPresent(report -> {
            int count = report.getReportCount();
            result.setCommunityReports(count);
            result.addWarning("🍁 " + count + " Canadian" + (count == 1 ? "" : "s") + " reported this as a scam");
            result.setRiskScore(Math.min(result.getRiskScore() + (count * 10), 100));
        });

        // Recalculate risk level
        int score = result.getRiskScore();
        if (score <= 10) result.setRiskLevel("LOW 🟢");
        else if (score <= 35) result.setRiskLevel("MEDIUM 🟡");
        else result.setRiskLevel("HIGH 🔴");

        // Gemini AI analysis
        String aiAnalysis = geminiService.analyzeUrl(url, result);
        if (aiAnalysis != null) result.setAiAnalysis(aiAnalysis);

        scanHistoryService.saveScan(user, "URL", url, result.getRiskLevel(), result.getRiskScore());
        return result;
    }

    public URLResult analyze(String url) {
        return analyze(url, null);
    }

    public EmailResult analyzeEmail(String emailBody, User user) {
        EmailResult result = EmailChecker.analyze(emailBody, safeBrowsingService);
        String aiAnalysis = geminiService.analyzeEmail(emailBody);
        if (aiAnalysis != null) result.setAiAnalysis(aiAnalysis);
        scanHistoryService.saveScan(user, "EMAIL", emailBody, result.getRiskLevel(), result.getRiskScore());
        return result;
    }

    public EmailResult analyzeEmail(String emailBody) {
        return analyzeEmail(emailBody, null);
    }
}
