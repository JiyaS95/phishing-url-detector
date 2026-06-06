# 🛡️ Phishing Detector

A phishing detection tool built in Java that analyzes URLs and emails for suspicious patterns and shows users a clear risk assessment. This project started as a simple URL checker and evolved into a full web app with a Chrome extension for real-time protection while browsing.

## Features

**URL Analysis**
- Analyze URLs for phishing indicators
- Detect suspicious keywords (login, secure, verify, etc.)
- Warn when a URL uses insecure **HTTP**
- Flag long URLs and excessive digits
- Detect too many subdomains
- Identify IP-based URLs
- Check against whitelist and blacklist
- Calculate overall risk score (Low, Medium, High)
- Powered by **Google Safe Browsing API** and **URLhaus** for known malware detection

**Email Analysis**
- Detect urgency and threat language
- Flag financial fraud indicators (Interac e-transfer, wire transfer, gift cards)
- Identify personal info harvesting (student ID, SIN, passport)
- Flag payment requests sent to personal email addresses
- Extract and scan URLs embedded in email body

**Chrome Extension**
- Popup UI to analyze any URL or email for instant risk assessment
- Adds risk badges next to each Google Search result
- Scans open Gmail emails for phishing indicators on demand

## Tech Stack

- Java 17
- Spring Boot
- HTML / CSS / JavaScript
- Maven
- Google Safe Browsing API (v4)
- URLhaus (abuse.ch)
- Docker
- Render (deployment)

## Run Locally

Make sure you have **Java 17+** installed.

```bash
cd phishing-detector-api/phishing-detector-api
./mvnw spring-boot:run
```

Add your API key to `src/main/resources/application.properties`:
```properties
spring.application.name=phishing-detector-api
safebrowsing.api.key=YOUR_KEY_HERE
server.port=${PORT:8080}
```

## Live Demo

🌐 [phishing-url-detector-je19.onrender.com](https://phishing-url-detector-je19.onrender.com)

> Free tier — first load may take 1 minute to wake up.

## Website

### Home Page
<img width="1361" height="838" alt="Home Page" src="https://github.com/user-attachments/assets/d76a6952-76f5-4abc-bf68-cb46514aa45e" />

### Low Risk Result
<img width="917" height="880" alt="Low Risk - Website" src="https://github.com/user-attachments/assets/8b42233e-2046-4747-8d0a-8a90159aa7f4" />

### High Risk Result
<img width="887" height="950" alt="High Risk - Website" src="https://github.com/user-attachments/assets/d359a796-5824-4ec9-a540-fd52ca026721" />

## Chrome Extension

### URL Analyzer — High Risk
<img width="461" height="587" alt="High Risk URL - Extension" src="https://github.com/user-attachments/assets/3ab2bb54-3c31-45be-b37b-48a5089e3583" />

### Email Analyzer — High Risk
<img width="487" height="742" alt="High Risk Email - Extension" src="https://github.com/user-attachments/assets/1766e132-3161-4a96-b164-33e4ce8b809b" />

### Google Search Badges
<img width="1450" height="762" alt="Google Search - Extension" src="https://github.com/user-attachments/assets/b5fa9dd0-ad47-43e3-87d0-d8bbe70f7234" />



