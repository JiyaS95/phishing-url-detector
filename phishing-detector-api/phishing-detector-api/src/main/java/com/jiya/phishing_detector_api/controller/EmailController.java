package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.detector.EmailResult;
import com.jiya.phishing_detector_api.service.PhishingService;
import org.springframework.web.bind.annotation.*;

@RestController
public class EmailController {

    private final PhishingService phishingService;

    public EmailController(PhishingService phishingService) {
        this.phishingService = phishingService;
    }

    @PostMapping("/check-email")
    public EmailResult checkEmail(@RequestBody String emailBody) {
        return phishingService.analyzeEmail(emailBody);
    }
}
