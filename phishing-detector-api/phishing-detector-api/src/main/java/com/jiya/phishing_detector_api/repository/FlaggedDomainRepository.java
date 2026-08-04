package com.jiya.phishing_detector_api.repository;
import com.jiya.phishing_detector_api.model.FlaggedDomain;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
public interface FlaggedDomainRepository extends JpaRepository<FlaggedDomain, Long> {
    Optional<FlaggedDomain> findByDomain(String domain);
}
