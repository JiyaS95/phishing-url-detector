package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.detector.URLResult;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.service.PhishingService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
public class PhishingController {

    private final PhishingService phishService;

    public PhishingController(PhishingService phishService) {
        this.phishService = phishService;
    }

    @GetMapping("/check")
    public URLResult checkURL(@RequestParam String url,
                              @AuthenticationPrincipal User user) {
        return phishService.analyze(url, user);
    }

    @PostMapping("/check/ai")
    public Map<String, String> checkAi(@RequestBody Map<String, Object> body) {
        String url = (String) body.get("url");

        Object riskScoreObj = body.get("riskScore");
        int riskScore = riskScoreObj instanceof Number
                ? ((Number) riskScoreObj).intValue()
                : 0;

        @SuppressWarnings("unchecked")
        List<String> warnings = (List<String>) body.get("warnings");

        String ai = phishService.getAiUrlAnalysis(url, riskScore, warnings);

        return Map.of("aiAnalysis", ai == null ? "" : ai);
    }
}