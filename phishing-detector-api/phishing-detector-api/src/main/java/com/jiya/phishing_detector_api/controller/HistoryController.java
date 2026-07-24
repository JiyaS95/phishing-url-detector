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
        if (user == null) return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        List<ScanHistory> history = scanHistoryService.getHistory(user);
        return ResponseEntity.ok(history);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteScan(@PathVariable Long id,
                                        @AuthenticationPrincipal User user) {
        if (user == null) return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        boolean exists = scanHistoryService.existsForUser(id, user);
        if (!exists) return ResponseEntity.status(404).body(Map.of("error", "Scan not found"));
        scanHistoryService.deleteScan(id, user);
        return ResponseEntity.ok(Map.of("message", "Deleted"));
    }

    @DeleteMapping("/all")
    public ResponseEntity<?> deleteAll(@AuthenticationPrincipal User user) {
        if (user == null) return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        List<ScanHistory> history = scanHistoryService.getHistory(user);
        if (history.isEmpty()) return ResponseEntity.ok(Map.of("message", "Nothing to delete"));
        scanHistoryService.deleteAll(user);
        return ResponseEntity.ok(Map.of("message", "All history cleared"));
    }
}
