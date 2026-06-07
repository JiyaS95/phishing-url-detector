package com.jiya.phishing_detector_api.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import java.util.List;
import java.util.Map;

@Service
public class GeminiService {

    @Value("${gemini.api.key}")
    private String apiKey;

    private final WebClient webClient = WebClient.create("https://generativelanguage.googleapis.com");

    public String analyzeEmail(String emailBody) {
        try {
            String prompt = "You are a cybersecurity expert specializing in phishing and scam detection. " +
                "Analyze the following email and determine if it is a scam, phishing attempt, or legitimate. " +
                "Be concise — 2-3 sentences max. Start with SCAM, PHISHING, SUSPICIOUS, or LEGITIMATE. " +
                "Explain the key reason why.\n\nEmail:\n" + emailBody;

            Map<String, Object> requestBody = Map.of(
                "contents", List.of(
                    Map.of("parts", List.of(
                        Map.of("text", prompt)
                    ))
                )
            );

            Map response = webClient.post()
                .uri("/v1beta/models/gemini-3.1-flash-lite:generateContent?key=" + apiKey)
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            if (response == null) return null;

            // Extract text from response: response.candidates[0].content.parts[0].text
            List candidates = (List) response.get("candidates");
            if (candidates == null || candidates.isEmpty()) return null;
            Map candidate = (Map) candidates.get(0);
            Map content = (Map) candidate.get("content");
            List parts = (List) content.get("parts");
            Map part = (Map) parts.get(0);
            return (String) part.get("text");

        } catch (Exception e) {
            System.out.println("Gemini API error: " + e.getMessage());
            return null;
        }
    }
}
