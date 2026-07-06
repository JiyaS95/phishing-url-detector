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
        if (user == null) return; // don't save if not logged in
        ScanHistory scan = new ScanHistory();
        scan.setUser(user);
        scan.setScanType(scanType);
        // truncate long email bodies for storage
        if (inputText != null && inputText.length() > 500) {
            inputText = inputText.substring(0, 500) + "...";
        }
        scan.setInputText(inputText);
        scan.setRiskLevel(riskLevel);
        scan.setRiskScore(riskScore);
        scanHistoryRepository.save(scan);
    }

    public List<ScanHistory> getHistory(User user) {
        return scanHistoryRepository.findByUserOrderByScannedAtDesc(user);
    }
}
