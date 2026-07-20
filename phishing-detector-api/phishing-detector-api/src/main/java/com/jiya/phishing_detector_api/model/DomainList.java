package com.jiya.phishing_detector_api.model;

import jakarta.persistence.*;

@Entity
@Table(name = "domain_list")
public class DomainList {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String domain;

    @Column(nullable = false)
    private String listType; // "WHITELIST" or "BLACKLIST"

    @Column
    private String reason;

    @Column
    private boolean communityReported = false;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
    public String getListType() { return listType; }
    public void setListType(String listType) { this.listType = listType; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public boolean isCommunityReported() { return communityReported; }
    public void setCommunityReported(boolean communityReported) { this.communityReported = communityReported; }
}
