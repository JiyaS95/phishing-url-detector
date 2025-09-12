# Phishing URL Detector
A Java-based phishing URL detector that analyzes links for suspicious patterns and warns users about potential risks.

## Features
- Check URLs against whitelist and blacklist
- Detect suspicious keywords in URLs
- Warn if URL uses insecure http
- Flag long URLs and excessive digits
- Detect too many subdomains
- Identify URLs that use IP addresses
- Calculate overall risk score (Low, Medium, High)

## Compile
javac src/main/java/*.java

## Run
java -cp src/main/java Main

## Notes
- URLs in the blacklist result in immediate high risk
- Risk Score Ranges
- --> 0-20: Low Risk
- --> 21-50: Medium Risk
- --> 51-100: High Risk

## Example
<img width="591" height="280" alt="image" src="https://github.com/user-attachments/assets/4840bfba-0280-4b5c-809f-0abeaeded2f2" />

