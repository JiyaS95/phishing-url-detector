package com.jiya.phishing_detector_api.repository;

import com.jiya.phishing_detector_api.model.ScanHistory;
import com.jiya.phishing_detector_api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {
    List<ScanHistory> findByUserOrderByScannedAtDesc(User user);
}
