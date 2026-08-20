package com.jiya.phishing_detector_api.service;

import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;

@Service
public class MailService {

    @Value("${gmail.client-id}")
    private String clientId;

    @Value("${gmail.client-secret}")
    private String clientSecret;

    @Value("${gmail.refresh-token}")
    private String refreshToken;

    @Value("${spring.mail.username}")
    private String fromAddress;

    private final WebClient webClient = WebClient.builder().build();

    private String getAccessToken() {
        Map<String, Object> response = webClient.post()
            .uri("https://oauth2.googleapis.com/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .bodyValue(
                "client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&refresh_token=" + refreshToken +
                "&grant_type=refresh_token"
            )
            .retrieve()
            .bodyToMono(Map.class)
            .block();

        if (response == null || response.get("access_token") == null) {
            throw new RuntimeException("Failed to obtain Gmail access token: " + response);
        }
        return (String) response.get("access_token");
    }

    public void sendPasswordResetCode(String toEmail, String code) {
        try {
            String accessToken = getAccessToken();
            String rawMessage = buildRawMessage(toEmail, code);

            webClient.post()
                .uri("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .bodyValue(Map.of("raw", rawMessage))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        } catch (Exception e) {
            throw new RuntimeException("Failed to send password reset email: " + e.getMessage(), e);
        }
    }

    private String buildRawMessage(String toEmail, String code) throws Exception {
        Session session = Session.getDefaultInstance(new Properties());
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(fromAddress));
        message.addRecipient(Message.RecipientType.TO, new InternetAddress(toEmail));
        message.setSubject("Your Alurtra password reset code");
        message.setText(
            "Your password reset code is: " + code + "\n\n" +
            "This code expires in 15 minutes. If you didn't request this, you can safely ignore this email."
        );

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        message.writeTo(buffer);
        return Base64.getUrlEncoder().encodeToString(buffer.toByteArray());
    }
    public void sendVerificationCode(String toEmail, String code) {
        try {
            String accessToken = getAccessToken();
            String rawMessage = buildVerificationMessage(toEmail, code);

            webClient.post()
                .uri("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .bodyValue(Map.of("raw", rawMessage))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        } catch (Exception e) {
            throw new RuntimeException("Failed to send verification email: " + e.getMessage(), e);
        }
    }

    private String buildVerificationMessage(String toEmail, String code) throws Exception {
        Session session = Session.getDefaultInstance(new Properties());
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(fromAddress));
        message.addRecipient(Message.RecipientType.TO, new InternetAddress(toEmail));
        message.setSubject("Verify your Alurtra account");
        message.setText(
            "Your email verification code is: " + code + "\n\n" +
            "This code expires in 15 minutes.\n" +
            "If you did not create an account, you can safely ignore this email."
        );

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        message.writeTo(buffer);
        return Base64.getUrlEncoder().encodeToString(buffer.toByteArray());
    }
}
