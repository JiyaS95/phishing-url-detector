package com.jiya.phishing_detector_api.detector;

import com.jiya.phishing_detector_api.service.SafeBrowsingService;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EmailChecker {

    public static EmailResult analyze(String emailBody, SafeBrowsingService safeBrowsing) {
        EmailResult result = new EmailResult();
        if (emailBody == null || emailBody.trim().isEmpty()) {
            result.setError("Email body is empty");
            return result;
        }
        int riskScore = 0;
        riskScore += checkUrgencyKeywords(result, emailBody);
        riskScore += checkSuspiciousLinks(result, emailBody, safeBrowsing);
        riskScore += checkCredentialRequests(result, emailBody);
        riskScore += checkThreatLanguage(result, emailBody);
        riskScore = Math.min(riskScore, 100);
        result.setRiskScore(riskScore);
        if (riskScore <= 20) result.setRiskLevel("LOW");
        else if (riskScore <= 50) result.setRiskLevel("MEDIUM");
        else result.setRiskLevel("HIGH");
        return result;
    }

    private static int checkUrgencyKeywords(EmailResult result, String body) {
        String lower = body.toLowerCase();
        String[] words = {"act now", "urgent", "immediately", "account suspended",
            "verify your account", "confirm your identity", "limited time",
            "your account will be closed", "action required", "response required"};
        int score = 0;
        for (String w : words) {
            if (lower.contains(w)) { result.addWarning("Urgency language: " + w); score += 15; }
        }
        return Math.min(score, 30);
    }

    private static int checkSuspiciousLinks(EmailResult result, String body, SafeBrowsingService safeBrowsing) {
        List<String> urls = extractUrls(body);
        int score = 0;
        for (String url : urls) {
            if (safeBrowsing.isMalicious(url)) {
                result.addWarning("Malicious URL (Google Safe Browsing): " + url);
                result.addSuspiciousUrl(url);
                score += 50;
            } else if (url.startsWith("http://")) {
                result.addWarning("Insecure link: " + url);
                result.addSuspiciousUrl(url);
                score += 10;
            }
        }
        return Math.min(score, 50);
    }

    private static int checkCredentialRequests(EmailResult result, String body) {
        String lower = body.toLowerCase();
        String[] words = {"enter your password", "confirm your password",
            "provide your credit card", "social security", "bank account number"};
        int score = 0;
        for (String w : words) {
            if (lower.contains(w)) { result.addWarning("Credential request: " + w); score += 20; }
        }
        return Math.min(score, 30);
    }

    private static int checkThreatLanguage(EmailResult result, String body) {
        String lower = body.toLowerCase();
        String[] words = {"will be terminated", "legal action", "suspended permanently",
            "unauthorized access", "security breach", "your account has been compromised"};
        int score = 0;
        for (String w : words) {
            if (lower.contains(w)) { result.addWarning("Threat language: " + w); score += 15; }
        }
        return Math.min(score, 25);
    }

    private static List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        Matcher m = Pattern.compile("https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+").matcher(text);
        while (m.find()) urls.add(m.group());
        return urls;
    }
}
