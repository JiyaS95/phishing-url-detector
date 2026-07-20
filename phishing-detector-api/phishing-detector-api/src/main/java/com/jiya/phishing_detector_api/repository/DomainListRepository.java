package com.jiya.phishing_detector_api.repository;

import com.jiya.phishing_detector_api.model.DomainList;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface DomainListRepository extends JpaRepository<DomainList, Long> {
    List<DomainList> findByListType(String listType);
    Optional<DomainList> findByDomain(String domain);
    boolean existsByDomain(String domain);
}
