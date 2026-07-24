package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.model.ScamReport;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.repository.ScamReportRepository;
import com.jiya.phishing_detector_api.service.DomainListService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/reports")
public class ScamReportController {

    private final ScamReportRepository scamReportRepository;
    private final DomainListService domainListService;

    public ScamReportController(ScamReportRepository scamReportRepository,
                                DomainListService domainListService) {
        this.scamReportRepository = scamReportRepository;
        this.domainListService = domainListService;
    }

    @PostMapping("/report")
    public ResponseEntity<?> report(@RequestBody Map<String, String> body,
                                    @AuthenticationPrincipal User user) {
        String urlOrEmail = body.get("urlOrEmail");
        String scamType = body.getOrDefault("scamType", "GENERAL");
        String description = body.getOrDefault("description", "");

        if (urlOrEmail == null || urlOrEmail.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "URL or email content is required"));
        }

        // Check if already reported — increment count
        Optional<ScamReport> existing = scamReportRepository.findByUrlOrEmailValue(urlOrEmail);
        if (existing.isPresent()) {
            ScamReport report = existing.get();
            report.setReportCount(report.getReportCount() + 1);
            scamReportRepository.save(report);
            // Auto-blacklist if reported 3+ times
            if (report.getReportCount() >= 3 && urlOrEmail.startsWith("http")) {
                try {
                    java.net.URL url = new java.net.URL(urlOrEmail);
                    domainListService.addToBlacklist(url.getHost(), "Community reported " + report.getReportCount() + " times", true);
                } catch (Exception ignored) {}
            }
            return ResponseEntity.ok(Map.of(
                "message", "Report recorded",
                "reportCount", report.getReportCount()
            ));
        }

        // New report
        ScamReport report = new ScamReport();
        report.setUrlOrEmail(urlOrEmail);
        report.setScamType(scamType);
        report.setDescription(description);
        report.setReportedBy(user);
        scamReportRepository.save(report);

        return ResponseEntity.ok(Map.of("message", "Thank you for reporting!", "reportCount", 1));
    }

    @GetMapping("/trending")
    public ResponseEntity<?> trending() {
        List<ScamReport> reports = scamReportRepository.findTop10ByOrderByReportCountDesc();
        return ResponseEntity.ok(reports);
    }
}
