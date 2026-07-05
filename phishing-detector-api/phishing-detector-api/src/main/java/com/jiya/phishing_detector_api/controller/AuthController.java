package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.dto.LoginRequest;
import com.jiya.phishing_detector_api.dto.RegisterRequest;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.repository.UserRepository;
import com.jiya.phishing_detector_api.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        if (userRepository.existsByEmail(req.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already registered"));
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
        Optional<User> userOpt = userRepository.findByEmail(req.getEmail());
        if (userOpt.isEmpty() || !passwordEncoder.matches(req.getPassword(), userOpt.get().getPassword())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid email or password"));
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
        return ResponseEntity.ok(Map.of(
            "name", user.getName(),
            "email", user.getEmail()
        ));
    }
}
