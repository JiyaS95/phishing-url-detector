package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.model.Feedback;
import com.jiya.phishing_detector_api.repository.FeedbackRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/feedback")
public class FeedbackController {

    private final FeedbackRepository feedbackRepository;

    public FeedbackController(FeedbackRepository feedbackRepository) {
        this.feedbackRepository = feedbackRepository;
    }

    @PostMapping
    public ResponseEntity<?> submitFeedback(@RequestBody Map<String, String> body) {
        String name = body.get("name");
        String email = body.get("email");
        String message = body.get("message");

        if (message == null || message.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Message is required"));
        }

        Feedback feedback = new Feedback();
        feedback.setName(name);
        feedback.setEmail(email);
        feedback.setMessage(message);
        feedbackRepository.save(feedback);

        return ResponseEntity.ok(Map.of("message", "Thanks for your feedback!"));
    }
}
