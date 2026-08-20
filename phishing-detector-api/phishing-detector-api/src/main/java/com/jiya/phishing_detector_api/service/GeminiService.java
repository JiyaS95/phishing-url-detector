package com.jiya.phishing_detector_api.service;

import com.jiya.phishing_detector_api.detector.URLResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.netty.http.client.HttpClient;
import java.util.concurrent.TimeUnit;
import java.util.List;
import java.util.Map;

@Service
public class GeminiService {

    @Value("${gemini.api.key}")
    private String apiKey;

    private final WebClient webClient = WebClient.builder()
        .baseUrl("https://generativelanguage.googleapis.com")
        .clientConnector(new ReactorClientHttpConnector(
            HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 20000)
                .doOnConnected(conn -> conn.addHandlerLast(new ReadTimeoutHandler(20, TimeUnit.SECONDS)))
        ))
        .build();

    private String callGemini(String prompt) {
        try {
            Map<String, Object> requestBody = Map.of(
                "contents", List.of(
                    Map.of("parts", List.of(Map.of("text", prompt)))
                )
            );

            Map response = webClient.post()
                .uri("/v1beta/models/gemini-3.5-flash-lite:generateContent?key=" + apiKey)
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(Map.class)
                .timeout(java.time.Duration.ofSeconds(20))
                .block();

            if (response == null) return null;
            List candidates = (List) response.get("candidates");
            if (candidates == null || candidates.isEmpty()) return null;
            Map candidate = (Map) candidates.get(0);
            Map contentMap = (Map) candidate.get("content");
            List parts = (List) contentMap.get("parts");
            Map part = (Map) parts.get(0);
            return (String) part.get("text");
        } catch (Exception e) {
            System.out.println("Gemini API error: " + e.getMessage());
            return null;
        }
    }

    public String analyzeEmail(String emailBody) {
        String prompt = "You are a cybersecurity expert specializing in phishing and scam detection. " +
            "Analyze the following email and determine if it is a scam, phishing attempt, or legitimate. " +
            "Be concise — 2-3 sentences max. Start with SCAM, PHISHING, SUSPICIOUS, or LEGITIMATE. " +
            "Explain the key reason why. Focus on Canadian-specific scams like CRA, OSAP, e-transfer fraud when relevant.\n\nEmail:\n" + emailBody;
        return callGemini(prompt);
    }

    public String analyzeUrl(String url, int riskScore, java.util.List<String> warningsList) {
        if (riskScore == 0 && (warningsList == null || warningsList.isEmpty())) {
            return null;
        }
        String warnings = warningsList != null ? String.join(", ", warningsList) : "none";
        String prompt = "You are a cybersecurity expert. Analyze this URL for phishing risk and explain in plain English. " +
            "Be concise — 2 sentences max. Start with SAFE, SUSPICIOUS, or DANGEROUS. " +
            "URL: " + url + ". " +
            "Detected warnings: " + warnings + ". " +
            "Risk score: " + riskScore + "/100. " +
            "Focus on Canadian users — mention if it impersonates Canadian banks, CRA, OSAP, Rogers, Bell, or Telus.";
        return callGemini(prompt);
    }

    public String analyzeUrl(String url, URLResult result) {
        return analyzeUrl(url, result.getRiskScore(), result.getWarnings());
    }
}
