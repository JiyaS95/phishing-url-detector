package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.dto.LoginRequest;
import com.jiya.phishing_detector_api.dto.RegisterRequest;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.repository.UserRepository;
import com.jiya.phishing_detector_api.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.DeleteMapping;
import java.util.Map;
import java.util.Optional;
import com.jiya.phishing_detector_api.repository.ScanHistoryRepository;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    private final ScanHistoryRepository scanHistoryRepository;

    private static final java.util.Set<String> DISPOSABLE_EMAIL_DOMAINS = java.util.Set.of(
        "mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com",
        "tempmail.com", "temp-mail.org", "throwawaymail.com", "getnada.com",
        "maildrop.cc", "trashmail.com", "fakeinbox.com", "sharklasers.com",
        "dispostable.com", "mintemail.com", "mailnesia.com", "spamgourmet.com",
        "mytemp.email", "moakt.com", "emailondeck.com", "mohmal.com",
        "tempinbox.com", "burnermail.io", "harakirimail.com", "mailcatch.com"
    );

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil,
                          ScanHistoryRepository scanHistoryRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.scanHistoryRepository = scanHistoryRepository;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        if (req.getEmail() == null || req.getEmail().isBlank()
            || req.getPassword() == null || req.getPassword().isBlank()
            || req.getName() == null || req.getName().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Name, email, and password are required"));
        }
        if (userRepository.existsByEmail(req.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already registered"));
        }
        String emailDomain = req.getEmail().substring(req.getEmail().indexOf('@') + 1).toLowerCase();
        if (DISPOSABLE_EMAIL_DOMAINS.contains(emailDomain)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Please use a permanent email address, not a temporary/disposable one"));
        }
        User user = new User();
        user.setName(req.getName());
        user.setEmail(req.getEmail());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        userRepository.save(user);
        String token = jwtUtil.generateToken(user.getEmail());
        return ResponseEntity.ok(Map.of(
            "token", token,
            "name", user.getName(),
            "email", user.getEmail()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        if (req.getEmail() == null || req.getEmail().isBlank()
            || req.getPassword() == null || req.getPassword().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email and password are required"));
        }
        Optional<User> userOpt = userRepository.findByEmail(req.getEmail());
        if (userOpt.isEmpty() || !passwordEncoder.matches(req.getPassword(), userOpt.get().getPassword())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid email or password"));
        }
        User user = userOpt.get();
        String token = jwtUtil.generateToken(user.getEmail());
        return ResponseEntity.ok(Map.of(
            "token", token,
            "name", user.getName(),
            "email", user.getEmail()
        ));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@RequestAttribute(required = false) User user) {
        if (user == null) return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        long totalScans = scanHistoryRepository.countByUser(user);
        return ResponseEntity.ok(Map.of(
            "name", user.getName(),
            "email", user.getEmail(),
            "totalScans", totalScans,
            "memberSince", user.getCreatedAt() != null ? user.getCreatedAt().toString().substring(0, 10) : "N/A"
        ));
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestAttribute(required = false) User user,
                                             @RequestBody Map<String, String> body) {
        if (user == null) return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        String current = body.get("currentPassword");
        String newPass = body.get("newPassword");
        if (!passwordEncoder.matches(current, user.getPassword()))
            return ResponseEntity.badRequest().body(Map.of("error", "Current password is incorrect"));
        if (newPass == null || newPass.length() < 8)
            return ResponseEntity.badRequest().body(Map.of("error", "New password must be at least 8 characters"));
        user.setPassword(passwordEncoder.encode(newPass));
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "Password updated successfully"));
    }

    @DeleteMapping("/delete-account")
    public ResponseEntity<?> deleteAccount(@RequestAttribute(required = false) User user) {
        if (user == null) return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        userRepository.delete(user);
        return ResponseEntity.ok(Map.of("message", "Account deleted"));
    }
}
