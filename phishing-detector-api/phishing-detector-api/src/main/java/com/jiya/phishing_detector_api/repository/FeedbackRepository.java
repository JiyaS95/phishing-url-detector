package com.jiya.phishing_detector_api.repository;

import com.jiya.phishing_detector_api.model.Feedback;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FeedbackRepository extends JpaRepository<Feedback, Long> {
}
