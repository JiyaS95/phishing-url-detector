package com.jiya.phishing_detector_api.controller;

import com.jiya.phishing_detector_api.dto.LoginRequest;
import com.jiya.phishing_detector_api.dto.RegisterRequest;
import com.jiya.phishing_detector_api.model.User;
import com.jiya.phishing_detector_api.repository.UserRepository;
import com.jiya.phishing_detector_api.security.JwtUtil;
import com.jiya.phishing_detector_api.service.MailService;
import org.springframework.http.ResponseEntity;
import java.security.SecureRandom;
import java.time.LocalDateTime;
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
    private final MailService mailService;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final java.util.Set<String> DISPOSABLE_EMAIL_DOMAINS = java.util.Set.of(
        "mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com",
        "tempmail.com", "temp-mail.org", "throwawaymail.com", "getnada.com",
        "maildrop.cc", "trashmail.com", "fakeinbox.com", "sharklasers.com",
        "dispostable.com", "mintemail.com", "mailnesia.com", "spamgourmet.com",
        "mytemp.email", "moakt.com", "emailondeck.com", "mohmal.com",
        "tempinbox.com", "burnermail.io", "harakirimail.com", "mailcatch.com",
        "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de", "guerrillamail.net",
        "guerrillamail.org", "grr.la", "spam4.me", "pokemail.net", "trbvm.com",
        "mailnull.com", "tempr.email", "tmpmail.org", "tmpmail.net", "tmpeml.com",
        "10minutemail.net", "10minutemail.co.za", "20minutemail.com", "33mail.com",
        "anonbox.net", "deadaddress.com", "discard.email", "discardmail.com",
        "e4ward.com", "fakemailgenerator.com", "getairmail.com", "inboxbear.com",
        "jetable.org", "koszmail.pl", "mailcatch.co", "mail-temp.com",
        "mailtemp.info", "mailsac.com", "mytrashmail.com", "no-spam.ws",
        "spamex.com", "spambox.us", "spamfree24.org", "spamherelady.com",
        "tempail.com", "tempmailaddress.com", "tempmailo.com", "temp-mail.io",
        "vpn.st", "wegwerfemail.de", "wegwerfmail.de", "wh4f.org",
        "yopmail.net", "yopmail.fr", "cool.fr.nf", "jourrapide.com",
        "armyspy.com", "cuvox.de", "dayrep.com", "einrot.com",
        "fleckens.hu", "gustr.com", "rhyta.com", "superrito.com",
        "teleworm.us", "einmalmail.de", "kurzepost.de", "spoofmail.de",
        "trashmail.de", "trashmail.me", "trashmail.net", "trash-mail.com",
        "trash-mail.de", "wegwerfadresse.de", "0-mail.com", "1secmail.com",
        "1secmail.net", "1secmail.org", "correotemporal.org", "instant-mail.de",
        "mailtemporaire.fr", "mail-temporaire.fr", "boun.cr", "byom.de",
        "chammy.info", "devnullmail.com", "letthemeatspam.com", "mt2015.com",
        "objectmail.com", "proxymail.eu", "rcpt.at", "spam.la",
        "spamavert.com", "spamday.com", "spamfree.eu", "spamhole.com",
        "spaml.com", "spaml.de", "supergreatmail.com", "tafmail.com"
    );

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil,
                          ScanHistoryRepository scanHistoryRepository,
                          MailService mailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.scanHistoryRepository = scanHistoryRepository;
        this.mailService = mailService;
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

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email is required"));
        }
        Optional<User> userOpt = userRepository.findByEmail(email);
        // Always return success even if the email doesn't exist, so attackers can't
        // use this endpoint to discover which emails are registered.
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            String code = String.format("%06d", RANDOM.nextInt(1_000_000));
            user.setResetCode(code);
            user.setResetCodeExpiresAt(LocalDateTime.now().plusMinutes(15));
            userRepository.save(user);
            mailService.sendPasswordResetCode(user.getEmail(), code);
        }
        return ResponseEntity.ok(Map.of("message", "If that email is registered, a reset code has been sent."));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String code = body.get("code");
        String newPassword = body.get("newPassword");

        if (email == null || code == null || newPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email, code, and new password are required"));
        }
        if (newPassword.length() < 8) {
            return ResponseEntity.badRequest().body(Map.of("error", "New password must be at least 8 characters"));
        }

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired code"));
        }
        User user = userOpt.get();

        if (user.getResetCode() == null
            || !user.getResetCode().equals(code)
            || user.getResetCodeExpiresAt() == null
            || user.getResetCodeExpiresAt().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired code"));
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetCode(null);
        user.setResetCodeExpiresAt(null);
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "Password reset successfully"));
    }

    @DeleteMapping("/delete-account")
    public ResponseEntity<?> deleteAccount(@RequestAttribute(required = false) User user) {
        if (user == null) return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        userRepository.delete(user);
        return ResponseEntity.ok(Map.of("message", "Account deleted"));
    }
}
