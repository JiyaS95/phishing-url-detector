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
        riskScore += checkFinancialFraud(result, emailBody);
        riskScore += checkPersonalInfoRequests(result, emailBody);
        riskScore += checkPersonalEmailPayment(result, emailBody);

        riskScore = Math.min(riskScore, 100);
        result.setRiskScore(riskScore);

        if (riskScore <= 15) result.setRiskLevel("LOW");
        else if (riskScore <= 45) result.setRiskLevel("MEDIUM");
        else result.setRiskLevel("HIGH");

        return result;
    }

    private static int checkUrgencyKeywords(EmailResult result, String body) {
        String lower = body.toLowerCase();
        String[][] urgencyWords = {
            {"final warning", "30"},
            {"act now", "15"},
            {"immediately", "15"},
            {"account suspended", "20"},
            {"verify your account", "20"},
            {"confirm your identity", "20"},
            {"limited time", "10"},
            {"your account will be closed", "20"},
            {"action required", "15"},
            {"response required", "15"},
            {"final opportunity", "25"},
            {"last chance", "20"},
            {"urgent", "15"},
            {"grace period", "20"},
            {"immediate risk", "25"},
            {"failure to comply", "30"},
            {"failure to respond", "25"}
        };
        int score = 0;
        for (String[] entry : urgencyWords) {
            if (lower.contains(entry[0])) {
                result.addWarning("⚠️ Urgency language: \"" + entry[0] + "\"");
                score += Integer.parseInt(entry[1]);
            }
        }
        return Math.min(score, 40);
    }

    private static int checkSuspiciousLinks(EmailResult result, String body, SafeBrowsingService safeBrowsing) {
        List<String> urls = extractUrls(body);
        int score = 0;
        for (String url : urls) {
            if (safeBrowsing.isMalicious(url)) {
                result.addWarning("🚨 Malicious URL (Google Safe Browsing): " + url);
                result.addSuspiciousUrl(url);
                score += 50;
            } else if (url.startsWith("http://")) {
                result.addWarning("⚠️ Insecure link: " + url);
                result.addSuspiciousUrl(url);
                score += 10;
            }
        }
        return Math.min(score, 50);
    }

    private static int checkCredentialRequests(EmailResult result, String body) {
        String lower = body.toLowerCase();
        String[] words = {
            "enter your password", "confirm your password",
            "provide your credit card", "social security",
            "bank account number", "security question",
            "security answer", "student number", "student id"
        };
        int score = 0;
        for (String w : words) {
            if (lower.contains(w)) {
                result.addWarning("⚠️ Personal info request: \"" + w + "\"");
                score += 20;
            }
        }
        return Math.min(score, 40);
    }

    private static int checkThreatLanguage(EmailResult result, String body) {
        String lower = body.toLowerCase();
        String[][] threatWords = {
            {"will be terminated", "20"},
            {"legal action", "20"},
            {"suspended permanently", "25"},
            {"unauthorized access", "15"},
            {"security breach", "15"},
            {"your account has been compromised", "25"},
            {"deregistration", "25"},
            {"loss of student status", "25"},
            {"permanent implications", "20"},
            {"immigration", "15"},
            {"visa status", "15"},
            {"academic hold", "20"},
            {"irreversible", "25"},
            {"non-compliance", "20"},
            {"removal from all", "25"}
        };
        int score = 0;
        for (String[] entry : threatWords) {
            if (lower.contains(entry[0])) {
                result.addWarning("🚨 Threat language: \"" + entry[0] + "\"");
                score += Integer.parseInt(entry[1]);
            }
        }
        return Math.min(score, 50);
    }

    private static int checkFinancialFraud(EmailResult result, String body) {
        String lower = body.toLowerCase();
        String[] fraudWords = {
            "e-transfer", "etransfer", "interac",
            "wire transfer", "western union", "moneygram",
            "gift card", "bitcoin", "crypto payment",
            "send money", "transfer funds", "deposit required",
            "tuition deposit", "mandatory payment"
        };
        int score = 0;
        for (String w : fraudWords) {
            if (lower.contains(w)) {
                result.addWarning("🚨 Financial fraud indicator: \"" + w + "\"");
                score += 25;
            }
        }
        return Math.min(score, 50);
    }

    private static int checkPersonalInfoRequests(EmailResult result, String body) {
        String lower = body.toLowerCase();
        String[] personalWords = {
            "full name", "date of birth", "home address",
            "phone number", "passport", "drivers license",
            "sin number", "social insurance",
            "include your name", "include your student"
        };
        int score = 0;
        for (String w : personalWords) {
            if (lower.contains(w)) {
                result.addWarning("⚠️ Personal info harvesting: \"" + w + "\"");
                score += 20;
            }
        }
        return Math.min(score, 40);
    }

    // Checks if email asks to send money to a personal email (gmail, hotmail, etc.)
    private static int checkPersonalEmailPayment(EmailResult result, String body) {
        String lower = body.toLowerCase();
        int score = 0;
        boolean hasPaymentContext = lower.contains("e-transfer") || lower.contains("interac")
            || lower.contains("send money") || lower.contains("transfer") || lower.contains("payment");

        Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+\\-]+@(gmail|hotmail|yahoo|outlook|icloud)\\.com");
        Matcher matcher = emailPattern.matcher(body);

        if (hasPaymentContext && matcher.find()) {
            result.addWarning("🚨 Payment requested to personal email: " + matcher.group());
            score = 50;
        }
        return score;
    }

    private static List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        Matcher m = Pattern.compile("https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+").matcher(text);
        while (m.find()) urls.add(m.group());
        return urls;
    }
}
