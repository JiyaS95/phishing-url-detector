import java.util.Scanner;
import java.net.URL;
import java.net.MalformedURLException;
/*
javac src/main/java/Main.java
java -cp src/main/java Main
*/
public class Main {
    public static void main (String args[]) {
        Scanner scan = new Scanner (System.in);
        System.out.println("==== Phishing URL Detector ====");
        System.out.println("Enter a URL to check:");
        System.out.print(">>>> ");
        String url = scan.nextLine();
        System.out.println("You entered: "+url); 

        

        try {
            URL urlObj = new URL(url);
            System.out.println("Protocol: "+urlObj.getProtocol());
            System.out.println("Host: "+urlObj.getHost());
            System.out.println("Path: "+urlObj.getPath());
            
        }
        catch (MalformedURLException e) {
            System.out.println("❌ Invalid URL format");
        }
    }
}