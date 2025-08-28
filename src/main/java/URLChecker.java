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
            int dots = host.split("\\.").length;

            if (dots > 3) {
                result.addWarning("⚠️ Too many subdomains found (possible phishing)");
            }
            String[] keywords = {"login", "secure", "verify", "update", "account"}; //common or extra words that appear in the urls

            for (int i = 0; i < keywords.length; i++) {
                if (host.contains(keywords[i])) {
                    result.addWarning("⚠️ Suspicious keyword detected: "+keywords[i]);
                }
            }
            
        }
        catch (MalformedURLException e) {
            System.out.println("❌ Invalid URL format");
        }
        return result;
    }
}