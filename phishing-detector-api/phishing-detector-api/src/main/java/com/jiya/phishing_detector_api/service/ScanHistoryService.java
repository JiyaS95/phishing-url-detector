package com.jiya.phishing_detector_api.service;

import com.jiya.phishing_detector_api.model.ScanHistory;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.repository.ScanHistoryRepository;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class ScanHistoryService {

    private final ScanHistoryRepository scanHistoryRepository;

    public ScanHistoryService(ScanHistoryRepository scanHistoryRepository) {
        this.scanHistoryRepository = scanHistoryRepository;
    }

    public void saveScan(User user, String scanType, String inputText, String riskLevel, int riskScore) {
        if (user == null) return;
        final String finalInput = inputText;
        List<ScanHistory> existing = scanHistoryRepository.findByUserOrderByScannedAtDesc(user);
        boolean alreadySaved = existing.stream()
            .anyMatch(s -> finalInput != null && finalInput.equals(s.getInputText()));
        if (alreadySaved) return;

        ScanHistory scan = new ScanHistory();
        scan.setUser(user);
        scan.setScanType(scanType);
        String textToSave = inputText;
        if (textToSave != null && textToSave.length() > 500) {
            textToSave = textToSave.substring(0, 500) + "...";
        }
        scan.setInputText(textToSave);
        scan.setRiskLevel(riskLevel);
        scan.setRiskScore(riskScore);
        scanHistoryRepository.save(scan);
    }

    public List<ScanHistory> getHistory(User user) {
        return scanHistoryRepository.findByUserOrderByScannedAtDesc(user);
    }

    public void deleteScan(Long id, User user) {
        scanHistoryRepository.findById(id).ifPresent(scan -> {
            if (scan.getUser().getId().equals(user.getId())) {
                scanHistoryRepository.delete(scan);
            }
        });
    }

    public void deleteAll(User user) {
        List<ScanHistory> history = scanHistoryRepository.findByUserOrderByScannedAtDesc(user);
        scanHistoryRepository.deleteAll(history);
    }
}
