package com.jiya.phishing_detector_api.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@Service
public class WhoisService {

    @Value("${whois.api.key}")
    private String apiKey;

    private final WebClient webClient = WebClient.create("https://www.whoisxmlapi.com");

    public WhoisResult checkDomain(String domain) {
        // WHOIS API trial ended — disabled to prevent errors
        return null;
        /*
            Map response = webClient.get()
                .uri("/whoisserver/WhoisService?apiKey=" + apiKey + "&domainName=" + domain + "&outputFormat=JSON")
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            if (response == null) return null;

            Map whoisRecord = (Map) response.get("WhoisRecord");
            if (whoisRecord == null) return null;

            Map registryData = (Map) whoisRecord.get("registryData");
            if (registryData == null) return null;

            String createdDate = (String) registryData.get("createdDate");
            if (createdDate == null) return null;

            // Parse the date and calculate age in days
            LocalDate created = LocalDate.parse(createdDate.substring(0, 10));
            long ageInDays = LocalDate.now().toEpochDay() - created.toEpochDay();

            WhoisResult result = new WhoisResult();
            result.setCreatedDate(createdDate.substring(0, 10));
            result.setAgeInDays(ageInDays);
            return result;

        } catch (Exception e) {
            System.out.println("WHOIS error: " + e.getMessage());
            return null;
        }
        */
    }

    public static class WhoisResult {
        private String createdDate;
        private long ageInDays;

        public String getCreatedDate() { return createdDate; }
        public void setCreatedDate(String createdDate) { this.createdDate = createdDate; }
        public long getAgeInDays() { return ageInDays; }
        public void setAgeInDays(long ageInDays) { this.ageInDays = ageInDays; }
    }
}
