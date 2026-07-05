package com.jiya.phishing_detector_api.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scam_reports")
public class ScamReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "url_or_email", columnDefinition = "TEXT")
    private String urlOrEmail;

    @Column(name = "scam_type")
    private String scamType; // "CRA", "OSAP", "ROGERS", "GENERAL", etc.

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "report_count")
    private int reportCount = 1;

    @Column(name = "verified")
    private boolean verified = false;

    @Column(name = "reported_at")
    private LocalDateTime reportedAt = LocalDateTime.now();

    @ManyToOne
    @JoinColumn(name = "reported_by")
    private User reportedBy;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUrlOrEmail() { return urlOrEmail; }
    public void setUrlOrEmail(String urlOrEmail) { this.urlOrEmail = urlOrEmail; }
    public String getScamType() { return scamType; }
    public void setScamType(String scamType) { this.scamType = scamType; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public int getReportCount() { return reportCount; }
    public void setReportCount(int reportCount) { this.reportCount = reportCount; }
    public boolean isVerified() { return verified; }
    public void setVerified(boolean verified) { this.verified = verified; }
    public LocalDateTime getReportedAt() { return reportedAt; }
    public User getReportedBy() { return reportedBy; }
    public void setReportedBy(User reportedBy) { this.reportedBy = reportedBy; }
}
