import java.net.URL;
import java.net.MalformedURLException;

public class URLChecker {
    public static URLResult analyze(String url) {
        URLResult result = new URLResult();
        try {
            URL urlObj = new URL(url);
            result.setProtocol(urlObj.getProtocol()); //get the protocol from the URL and store it in the URLResult object
            result.setHost(urlObj.getHost());
            result.setPath(urlObj.getPath());
            String host = urlObj.getHost();
            
            int riskScore = 0; //Scoring system --> used to show risk level (low/medium/high)


            //checking for extra dots
            int dots = host.split("\\.").length;

            if (dots > 3) {
                result.addWarning("⚠️ Too many subdomains found (possible phishing)");
                riskScore = riskScore + 15;
            }
            
            
            //Check for extra keywords
            String[] keywords = {"login", "secure", "verify", "update", "account", "confirm", "payment", "banking", "transaction", "billing"}; //common or extra words that appear in the urls

            int keywordRisk = 0;
            for (int i = 0; i < keywords.length; i++) {
                if (host.contains(keywords[i])) {
                    result.addWarning("⚠️ Suspicious keyword detected: "+keywords[i]);
                    keywordRisk = keywordRisk + 15;
                }
            }
            if (keywordRisk > 30) {
                riskScore = riskScore + 30;
            }
            else {
                riskScore = riskScore + keywordRisk;
            }

            if (urlObj.getProtocol().equals("http")) {
                result.addWarning("⚠️ Connection is not secure (uses http instead of https)");
                riskScore = riskScore + 20;
            }

            //Check for long URLS
            if (url.length() > 100) {
                result.addWarning("⚠️ URL is very long (possible phishing)");
                riskScore = riskScore + 10;
            }
            int digitCount = 0;
            for (int i = 0; i < url.length(); i++) {
                char c = url.charAt(i);
                if (Character.isDigit(c)) {
                    ++digitCount;
                }
            }
            double digitPercent = ((double) digitCount / url.length()) * 100;
            if (digitPercent >= 30) {
                result.addWarning("⚠️ Too many digits detected (possible phishing)");
                riskScore = riskScore + 20;
            }
            
            //Check IP Address
            if (host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$") || host.contains(":")) {
                result.addWarning("⚠️ Domain is an IP Address (possible phishing)");
                riskScore = riskScore + 40;
            }
        }
        catch (MalformedURLException e) {
            System.out.println("❌ Invalid URL format");
        }
        result.setRiskScore(riskScore);
        return result;
    }
}