# 🛡️ Alurtra

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
- **AI-powered analysis** using Gemini to provide a natural language verdict on whether the email is legitimate, suspicious, or a phishing attempt
- AI verdict overrides heuristic risk level — if Gemini says LEGITIMATE, the result is marked LOW risk regardless of triggered keywords

**Chrome Extension**
- Popup UI to analyze any URL or email for instant risk assessment
- Adds risk badges next to each Google Search result
- Scans open Gmail, Outlook, and Yahoo Mail emails for phishing indicators on demand
- Displays AI analysis verdict directly in the in-page banner

## Tech Stack
- Java 17
- Spring Boot
- HTML / CSS / JavaScript
- Maven
- Google Safe Browsing API (v4)
- URLhaus (abuse.ch)
- Gemini AI API (gemini-3.1-flash-lite)
- Docker
- Render (deployment)

## Run Locally

Make sure you have **Java 17+** installed.
```bash
cd phishing-detector-api/phishing-detector-api
./mvnw spring-boot:run
```
Add your API keys to `src/main/resources/application.properties`:
```properties
spring.application.name=phishing-detector-api
safebrowsing.api.key=YOUR_KEY_HERE
gemini.api.key=YOUR_KEY_HERE
server.port=${PORT:8080}
```

## Live Demo

🌐 [phishing-url-detector-je19.onrender.com](https://phishing-url-detector-je19.onrender.com)

> Free tier — first load may take 1 minute to wake up.

## Website

### Home Page
<img width="1127" height="640" alt="image" src="https://github.com/user-attachments/assets/0bcbfb46-40f1-48bf-bd8d-6c179846abf6" />

### High Risk Result - URL
<img width="887" height="950" alt="High Risk - Website" src="https://github.com/user-attachments/assets/d359a796-5824-4ec9-a540-fd52ca026721" />

### Medium Risk Result - Email
<img width="712" height="965" alt="image" src="https://github.com/user-attachments/assets/f8aba9e9-0cc9-42f8-8307-6a4495ebb41c" />

## Chrome Extension

### URL Analyzer — High Risk
<img width="461" height="587" alt="High Risk URL - Extension" src="https://github.com/user-attachments/assets/3ab2bb54-3c31-45be-b37b-48a5089e3583" />

### Email Analyzer — Low Risk
<img width="467" height="745" alt="image" src="https://github.com/user-attachments/assets/ac49fa0e-96c3-4fee-b18d-9a7b7498c980" />

### In-Page Email Scanner — Medium Risk
<img width="1585" height="887" alt="image" src="https://github.com/user-attachments/assets/742d0adf-0236-4fec-bdc5-5566e6deddb2" />

### Google Search Badges
<img width="1450" height="762" alt="Google Search - Extension" src="https://github.com/user-attachments/assets/b5fa9dd0-ad47-43e3-87d0-d8bbe70f7234" />



