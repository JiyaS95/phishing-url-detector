# Phishing URL Detector
A web-based phishing URL detector built in Java that analyzes URLs for suspicious patterns and shows users a clear risk assessment. This project started as a simple URL checker and evolved into a full web app with a clean UI and real-time analysis.

## Features
- Analyze URLs for phishing indicators
- Detect suspicious keywords (login, secure, verify, etc.)
- Warn when a URL uses insecure **HTTP**
- Flag long URLs and excessive digits
- Detect too many subdomains
- Identify IP-based URLs
- Check against whitelist and blacklist
- Calculate overall risk score (Low, Medium, High)
- Display results directly in the browser

## Tech Stack
- Java 17
- Spring Boot
- HTML/CSS/JavaScript
- Maven

## Run
Make sure you have **Java 17+** installed.
- ./mvnw spring-boot:run

## Home Page
<img width="1915" height="675" alt="home-page" src="https://github.com/user-attachments/assets/b3339233-c3ab-45fe-8f01-8d534c5d8dd0" />

## Valid URL Result
<img width="1916" height="930" alt="valid-url" src="https://github.com/user-attachments/assets/9ec987b4-896a-46f7-a78c-13013863ecce" />

## Invalid URL Result
<img width="1918" height="825" alt="invalid-url" src="https://github.com/user-attachments/assets/c798dbe4-406c-4761-a9c4-89f43f5a9626" />

## Medium Risk Example
<img width="1916" height="971" alt="medium-risk" src="https://github.com/user-attachments/assets/7f03d22c-a8fc-403c-becf-5eacc0d20cd8" />

