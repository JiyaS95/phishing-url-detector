# <img width="35" height="30" alt="Alurtra Simple Logo 3-Photoroom" src="https://github.com/user-attachments/assets/e513e246-6a0b-4374-8b6c-d621b7d85419" /> &nbsp; Alurtra 


A phishing detection tool built in Java that analyzes URLs and emails for suspicious patterns and gives users a clear risk assessment. The project started as a simple URL checker and gradually evolved into a full web app. It now includes a Chrome extension and an Outlook Add-in, providing real-time protection while browsing and reading emails.

## Features
**URL Analysis**
- Analyze URLs for phishing indicators
- Detect suspicious keywords (login, secure, verify, etc.)
- Warn when a URL uses insecure HTTP
- Flag long URLs and excessive digits
- Detect numerous subdomains
- Identify IP-based URLs
- Check against whitelist and blacklist (whitelisted domains skip all other checks and are always marked LOW risk)
- Calculate overall risk score (Low, Medium, High)
- Powered by Google Safe Browsing API and URLhaus for known malware detection
- Flags domains impersonating Canadian government agencies (CRA, Service Canada) or Canadian banks (RBC, TD, Scotiabank, BMO, CIBC, etc.)
- AI-powered contextual analysis (Google Gemini) for additional risk insight

**Email Analysis**
- Detect urgency and threat language
- Flag financial fraud indicators (Interac e-transfer, wire transfer, gift cards)
- Identify personal info harvesting (student ID, SIN, passport)
- Flag payment requests sent to personal email addresses
- Extract and scan URLs embedded in email body
- AI-powered analysis using Gemini to provide a natural language verdict on whether the email is legitimate, suspicious, or a phishing attempt
- AI verdict overrides heuristic risk level (eg. if Gemini says LEGITIMATE, the result is marked LOW risk regardless of triggered keywords)

**Chrome Extension**
- Popup UI to analyze any URL or email for instant risk assessment
- Adds risk badges next to each Google Search result (eg. LOW 10/100)
- Adds a "Scan Email" button inside Gmail, Outlook (web), and Yahoo Mail for on-demand full-body AI analysis
- Automatically scans every link inside an opened email in the background and flags risky ones with a small warning icon next to the link, without blocking or altering the rest of the email
- Displays AI analysis verdict directly in the in-page banner

**Outlook Add-in**
- A dedicated Outlook Add-in (separate from the Chrome extension) that adds a task pane directly inside Outlook desktop and web
- "Scan This Email" button reads the open email via the Office.js API and sends it to the same `/check-email` backend used everywhere else
- Installed by downloading a manifest file from the website and sideloading it via Outlook's "My Add-ins" panel 

**Website**
- Full account system: registration, login, and password reset via a 6-digit emailed code (valid 15 minutes)
- Scan history for logged-in users
- Community-reported scams page
- Install instructions for both the Chrome extension and the Outlook Add-in, including guidance for Yahoo Mail users (covered by the Chrome extension, since Yahoo has no separate add-in platform)


## Tech Stack
- Java 17
- Spring Boot (REST API, Spring Security, JPA/Hibernate)
- PostgreSQL (database)
- HTML / CSS / JavaScript (website frontend)
- JavaScript + Webpack (Outlook Add-in task pane)
- Chrome Extension (Manifest V3)
- Maven
- Google Safe Browsing API (v4)
- URLhaus (abuse.ch)
- Gemini AI API (gemini-3.1-flash-lite)
- Gmail API (OAuth2) for sending password reset codes
- Docker
- Render (deployment)

## Run Locally

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

# Mail (Gmail API over HTTPS)
spring.mail.username=YOUR_GMAIL_ADDRESS
gmail.client-id=YOUR_OAUTH_CLIENT_ID
gmail.client-secret=YOUR_OAUTH_CLIENT_SECRET
gmail.refresh-token=YOUR_OAUTH_REFRESH_TOKEN
```

## Live Demo
**https://www.alurtra.linkpc.net/**
<br>
<br>

## Website

### Home Page
<img width="1887" height="812" alt="Home Page" src="https://github.com/user-attachments/assets/64a13b6a-9959-4c66-8c03-45cc133fae33" />

### High Risk Result - URL
<img width="821" height="946" alt="High Risk - Website" src="https://github.com/user-attachments/assets/54ec8bcd-99d5-4f7d-bb00-f87a25826177" />

### Medium Risk Result - Email
<img width="712" height="965" alt="image" src="https://github.com/user-attachments/assets/f8aba9e9-0cc9-42f8-8307-6a4495ebb41c" />


## Chrome Extension

### URL Analyzer — High Risk
<img width="458" height="588" alt="High Risk URL - Extension" src="https://github.com/user-attachments/assets/9cce339b-0dcc-4de9-89f9-7e67fed54c61" />

### Email Analyzer — Low Risk
<img width="467" height="745" alt="image" src="https://github.com/user-attachments/assets/ac49fa0e-96c3-4fee-b18d-9a7b7498c980" />

### In-Page Email Scanner — Medium Risk
<img width="1585" height="887" alt="image" src="https://github.com/user-attachments/assets/742d0adf-0236-4fec-bdc5-5566e6deddb2" />

### Google Search Badges
<img width="1450" height="762" alt="Google Search - Extension" src="https://github.com/user-attachments/assets/b5fa9dd0-ad47-43e3-87d0-d8bbe70f7234" />



