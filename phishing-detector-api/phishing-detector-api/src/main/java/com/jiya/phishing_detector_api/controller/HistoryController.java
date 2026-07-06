package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.model.ScanHistory;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.service.ScanHistoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/history")
public class HistoryController {

    private final ScanHistoryService scanHistoryService;

    public HistoryController(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    @GetMapping
    public ResponseEntity<?> getHistory(@AuthenticationPrincipal User user) {
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        List<ScanHistory> history = scanHistoryService.getHistory(user);
        return ResponseEntity.ok(history);
    }
}
