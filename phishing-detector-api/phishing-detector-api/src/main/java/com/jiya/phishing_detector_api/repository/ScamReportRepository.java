package com.jiya.phishing_detector_api.repository;

import com.jiya.phishing_detector_api.model.ScamReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;
import java.util.Optional;

public interface ScamReportRepository extends JpaRepository<ScamReport, Long> {
    Optional<ScamReport> findByUrlOrEmail(String urlOrEmail);
    List<ScamReport> findTop10ByOrderByReportCountDesc();

    @Query("SELECT s FROM ScamReport s ORDER BY s.reportedAt DESC")
    List<ScamReport> findRecentReports();
}
