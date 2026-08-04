package com.jiya.phishing_detector_api.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "flagged_domains")
public class FlaggedDomain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String domain;

    @Column(nullable = false)
    private int flagCount = 0;

    @Column
    private LocalDateTime lastFlaggedAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
    public int getFlagCount() { return flagCount; }
    public void setFlagCount(int flagCount) { this.flagCount = flagCount; }
    public LocalDateTime getLastFlaggedAt() { return lastFlaggedAt; }
    public void setLastFlaggedAt(LocalDateTime lastFlaggedAt) { this.lastFlaggedAt = lastFlaggedAt; }
}
