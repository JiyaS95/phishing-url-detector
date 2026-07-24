package com.jiya.phishing_detector_api.repository;

import com.jiya.phishing_detector_api.model.ScanHistory;
import com.jiya.phishing_detector_api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {
    List<ScanHistory> findByUserOrderByScannedAtDesc(User user);

    @Modifying
    @Transactional
    @Query("DELETE FROM ScanHistory s WHERE s.user = :user")
    void deleteAllByUser(User user);
}
