package com.jiya.phishing_detector_api.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import java.util.List;
import java.util.Map;

@Service
public class SafeBrowsingService {

    @Value("${safebrowsing.api.key}")
    private String apiKey;

    private final WebClient googleClient = WebClient.create("https://safebrowsing.googleapis.com");
    private final WebClient urlhausClient = WebClient.create("https://urlhaus-api.abuse.ch");

    // Returns true if either Google or URLhaus flags the URL as dangerous
    public boolean isMalicious(String url) {
        return checkGoogleSafeBrowsing(url) || checkURLhaus(url);
    }

    private boolean checkGoogleSafeBrowsing(String url) {
        try {
            Map<String, Object> requestBody = Map.of(
                "client", Map.of("clientId", "phishing-detector", "clientVersion", "1.0.0"),
                "threatInfo", Map.of(
                    "threatTypes", List.of("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"),
                    "platformTypes", List.of("ANY_PLATFORM"),
                    "threatEntryTypes", List.of("URL"),
                    "threatEntries", List.of(Map.of("url", url))
                )
            );
            Map response = googleClient.post()
                .uri("/v4/threatMatches:find?key=" + apiKey)
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(Map.class)
                .timeout(java.time.Duration.ofSeconds(8))
                .block();
            return response != null && response.containsKey("matches");
        } catch (Exception e) {
            System.out.println("Google Safe Browsing error: " + e.getMessage());
            return false;
        }
    }

    private boolean checkURLhaus(String url) {
        try {
            // URLhaus lookup API - free, no key needed
            String formBody = "url=" + java.net.URLEncoder.encode(url, "UTF-8");
            Map response = urlhausClient.post()
                .uri("/v1/url/")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue(formBody)
                .retrieve()
                .bodyToMono(Map.class)
                .timeout(java.time.Duration.ofSeconds(4))
                .block();

            if (response == null) return false;
            String queryStatus = (String) response.get("query_status");
            // "is_available" means it's a known malicious URL in their database
            return "is_available".equals(queryStatus);
        } catch (Exception e) {
            System.out.println("URLhaus error: " + e.getMessage());
            return false;
        }
    }
}
