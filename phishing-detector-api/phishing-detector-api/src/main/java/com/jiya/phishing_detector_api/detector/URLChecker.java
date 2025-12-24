package com.jiya.phishing_detector_api.detector;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;


public class URLChecker {
    public static URLResult analyze(String url, Set<String>whitelistSet, Set<String>blacklistSet) {
        URLResult result = new URLResult();
        URL urlObj;
        try {
            urlObj = new URL(url);
            
        }
        catch (MalformedURLException e) {
            result = new URLResult();
            result.setError("❌ Invalid URL format");
            return result; //return empty result if URL is invalid
        }

        String host = urlObj.getHost();
        result.setProtocol(urlObj.getProtocol()); //get the protocol from the URL and store it in the URLResult object
        result.setDomain(urlObj.getHost());
        result.setPath(urlObj.getPath());
            
        int riskScore = 0; //Scoring system --> used to show risk level (low/medium/high)
        
        //Call each method and store corresponding risk score
        riskScore = riskScore + checkBlacklist(result, host, blacklistSet);
        if (riskScore == 100) { //exit and print immediately if domain is blacklisted
            result.setRiskScore(riskScore);
            return result;
        }
        riskScore = riskScore + checkWhitelist(result, host, whitelistSet);
        riskScore = riskScore + checkSubdomains(result, host);
        riskScore = riskScore + checkKeywords(result, host);
        riskScore = riskScore + checkProtocol(result, urlObj);
        riskScore = riskScore + checkDigitsAndLength(result, url);
        riskScore = riskScore + checkIPAddress(result, host);
        result.setRiskScore(riskScore);
        return result;
    }

    //Check methods --> checks and adds warnings, returns corresponding risk contribution

    public static int checkBlacklist (URLResult result, String host, Set<String> blacklistSet) {
        Iterator<String> it = blacklistSet.iterator();

        while (it.hasNext()) {
            String badDomain = it.next();
            if (host.endsWith(badDomain)) {
                result.addWarning("⚠️ Domain is blacklisted (HIGH RISK!!)");
                return 100; //immediate max risk
            }
        }
        
        
        return 0;
    }

    public static int checkWhitelist (URLResult result, String host, Set<String> whitelistSet) {
        Iterator<String> it = whitelistSet.iterator();
        while (it.hasNext()) {
            String safeDomain = it.next();
            if (host.endsWith(safeDomain)) {
                result.addWarning("✅ Domain is whitelisted (LOW RISK 🟢)");
            }
        }
        return 0;
    }

    public static int checkSubdomains (URLResult result, String host) {
        int riskScore = 0;
        int dots = host.split("\\.").length;

        if (dots > 3) {
            result.addWarning("⚠️ Too many subdomains found (possible phishing)");
            riskScore = 15;
        }
        return riskScore;
    }

    public static int checkKeywords (URLResult result, String host) {
        int riskScore = 0;
        String[] keywords = {"login", "secure", "verify", "update", "account", "confirm", "payment", "banking", "transaction", "billing"}; //common or extra words that appear in the urls

        int keywordRisk = 0;
        for (int i = 0; i < keywords.length; i++) {
            if (host.contains(keywords[i])) {
                result.addWarning("⚠️ Suspicious keyword detected: "+keywords[i]);
                keywordRisk = keywordRisk + 15;
            }
        }
        if (keywordRisk > 30) {
            riskScore = 30; //cap the keyword risk at 30
        }
        else {
            riskScore = keywordRisk;
        }

        return riskScore;
    }

    public static int checkProtocol (URLResult result, URL urlObj) {
        int riskScore = 0;
        if (urlObj.getProtocol().equals("http")) {
            result.addWarning("⚠️ Connection is not secure (uses http instead of https)");
            riskScore = 20;
        }
        return riskScore;
    }

    public static int checkDigitsAndLength (URLResult result, String url) {
        //Checks for long URLs and URLs containing too many digits
        int riskScore = 0;
        if (url.length() > 100) {
            result.addWarning("⚠️ URL is very long (possible phishing)");
            riskScore = 10;
        }
        int digitCount = 0;
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (Character.isDigit(c)) {
                ++digitCount;
            }
        }
        double digitPercent = ((double) digitCount / url.length()) * 100;
        if (digitPercent >= 30) {
            result.addWarning("⚠️ Too many digits detected (possible phishing)");
            riskScore = 20;
        }
        return riskScore;
    }

    public static int checkIPAddress (URLResult result, String host) {
        int riskScore = 0;
        if (host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$") || host.contains(":")) {
            result.addWarning("⚠️ Domain is an IP Address (possible phishing)");
            riskScore = 40;
        }
        return riskScore;
    }
}