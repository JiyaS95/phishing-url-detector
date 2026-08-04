package com.jiya.phishing_detector_api.service;

import com.jiya.phishing_detector_api.model.DomainList;
import com.jiya.phishing_detector_api.model.FlaggedDomain;
import com.jiya.phishing_detector_api.repository.DomainListRepository;
import com.jiya.phishing_detector_api.repository.FlaggedDomainRepository;
import java.time.LocalDateTime;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class DomainListService {

    private final DomainListRepository domainListRepository;
    private final FlaggedDomainRepository flaggedDomainRepository;

    private static final int AUTO_BLACKLIST_THRESHOLD = 3;

    public DomainListService(DomainListRepository domainListRepository, FlaggedDomainRepository flaggedDomainRepository) {
        this.domainListRepository = domainListRepository;
        this.flaggedDomainRepository = flaggedDomainRepository;
    }

    // Seed default entries on startup if database is empty
    @PostConstruct
    public void seedDefaults() {
        if (domainListRepository.count() == 0) {
            String[][] whitelist = {
                {"google.com", "Google - verified safe"},
                {"github.com", "GitHub - verified safe"},
                {"walmart.com", "Walmart - verified safe"},
                {"amazon.com", "Amazon - verified safe"},
                {"canada.ca", "Government of Canada"},
                {"cra-arc.gc.ca", "Canada Revenue Agency"},
                {"osap.gov.on.ca", "OSAP - Ontario Student Assistance"},
                {"uoft.ca", "University of Toronto"},
                {"rbc.com", "Royal Bank of Canada"},
                {"td.com", "TD Bank"},
                {"scotiabank.com", "Scotiabank"},
                {"cibc.com", "CIBC"},
                {"bmo.com", "BMO"},
                {"rogers.com", "Rogers Communications"},
                {"bell.ca", "Bell Canada"},
                {"telus.com", "Telus"},
                {"alurtra.linkpc.net", "Alurtra - our own site"},
                {"www.alurtra.linkpc.net", "Alurtra - our own site"}
            };
            for (String[] entry : whitelist) {
                DomainList d = new DomainList();
                d.setDomain(entry[0]);
                d.setListType("WHITELIST");
                d.setReason(entry[1]);
                domainListRepository.save(d);
            }

            String[][] blacklist = {
                {"phishing.com", "Known phishing domain"},
                {"badsite.com", "Known malicious domain"},
                {"cra-refund.com", "CRA impersonation scam"},
                {"cra-tax-refund.ca", "CRA impersonation scam"},
                {"service-canada-benefits.com", "Service Canada impersonation"},
                {"osap-grant.com", "OSAP impersonation scam"},
                {"canada-cerb-payment.com", "CERB impersonation scam"}
            };
            for (String[] entry : blacklist) {
                DomainList d = new DomainList();
                d.setDomain(entry[0]);
                d.setListType("BLACKLIST");
                d.setReason(entry[1]);
                domainListRepository.save(d);
            }

            System.out.println("Domain list seeded with defaults.");
        }
    }

    public Set<String> getWhitelist() {
        return domainListRepository.findByListType("WHITELIST")
            .stream().map(DomainList::getDomain).collect(Collectors.toSet());
    }

    public Set<String> getBlacklist() {
        return domainListRepository.findByListType("BLACKLIST")
            .stream().map(DomainList::getDomain).collect(Collectors.toSet());
    }

    public void addToBlacklist(String domain, String reason, boolean communityReported) {
        if (!domainListRepository.existsByDomain(domain)) {
            DomainList d = new DomainList();
            d.setDomain(domain);
            d.setListType("BLACKLIST");
            d.setReason(reason);
            d.setCommunityReported(communityReported);
            domainListRepository.save(d);
        }
    }

    public void addToWhitelist(String domain, String reason) {
        if (!domainListRepository.existsByDomain(domain)) {
            DomainList d = new DomainList();
            d.setDomain(domain);
            d.setListType("WHITELIST");
            d.setReason(reason);
            domainListRepository.save(d);
        }
    }

    // Called whenever a scan comes back HIGH risk. Tracks how many times a domain
    // has been independently flagged, and auto-blacklists it once it crosses the
    // threshold - avoids one single false positive permanently blocking a real site.
    public void recordHighRiskFlag(String domain) {
        if (domain == null || domain.isBlank()) return;
        if (domainListRepository.existsByDomain(domain)) return; // already whitelisted or blacklisted

        FlaggedDomain flagged = flaggedDomainRepository.findByDomain(domain)
            .orElseGet(() -> {
                FlaggedDomain f = new FlaggedDomain();
                f.setDomain(domain);
                f.setFlagCount(0);
                return f;
            });

        flagged.setFlagCount(flagged.getFlagCount() + 1);
        flagged.setLastFlaggedAt(LocalDateTime.now());
        flaggedDomainRepository.save(flagged);

        if (flagged.getFlagCount() >= AUTO_BLACKLIST_THRESHOLD) {
            addToBlacklist(domain, "Auto-blacklisted after " + flagged.getFlagCount() + " high-risk scans", false);
        }
    }
}
