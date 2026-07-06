package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.detector.URLResult;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.service.PhishingService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

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
}
