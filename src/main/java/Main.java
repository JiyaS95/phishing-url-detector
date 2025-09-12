import java.util.Scanner;
import java.util.Set;
import java.util.HashSet;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;

/*
javac src/main/java/Main.java
java -cp src/main/java Main
*/
public class Main {
    public static void main (String args[]) {
        Scanner scan = new Scanner (System.in);
        Set<String> whitelistSet = new HashSet<>();
        Set<String> blacklistSet = new HashSet<>();

        System.out.println("==== Phishing URL Detector ====");
        System.out.println("Enter a URL to check:");
        System.out.print(">>>> ");
        String url = scan.nextLine();
        System.out.println("You entered: "+url); 

        readWhitelist(whitelistSet);
        readBlacklist(blacklistSet);

        URLResult result = URLChecker.analyze(url, whitelistSet, blacklistSet);
        result.print();

        scan.close();
    }


    //Read the whitelist
    public static void readWhitelist(Set<String> whitelistSet) {
        try (BufferedReader br = new BufferedReader(new FileReader ("src/main/java/whitelist.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                whitelistSet.add(line.trim());
            }
        }
        catch (IOException e) {
            System.out.println("Error reading white list file: "+e.getMessage());
        }
    }

    //Read the blacklist
    public static void readBlacklist(Set<String> blacklistSet) {
        try (BufferedReader br = new BufferedReader(new FileReader ("src/main/java/blacklist.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                blacklistSet.add(line.trim());
            }
        }
        catch (IOException e) {
            System.out.println("Error reading black list file: "+e.getMessage());
        }
    }
}