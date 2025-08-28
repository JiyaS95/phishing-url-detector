import java.util.List;
import java.util.ArrayList;

public class URLResult {
    private String protocol;
    private String domain;
    private String path;
    private List<String> warnings = new ArrayList<>();

    public void setProtocol (String protocol) {
        this.protocol = protocol;
    }

    public void setHost (String domain) {
        this.domain = domain;
    }

    public void setPath (String path) {
        this.path = path;
    }

    public void addWarning (String warning) {
        warnings.add(warning);
    }

    public void print() {
        System.out.println("Protocol: "+protocol);
        System.out.println("Domain: "+domain);
        System.out.println("Path: "+path);

        if (warnings.isEmpty()) {
            System.out.println("✅ No warnings detected");
        }
        else {
            System.out.println("Warnings: ");
            for (int i = 0; i < warnings.size(); i++) {
                System.out.println(" - "+warnings.get(i));
            }
        }
    }
}