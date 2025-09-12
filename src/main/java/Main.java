import java.util.Scanner;
import java.util.Set;
import java.util.HashSet;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;
/*
Author: Jiya Shukla
Date: September 11th, 2025
Program Description: Detects Phishing URLs
*/

/*
javac src/main/java/*.java
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
        System.out.println("\nYou entered: "+url); 

        //Populate whitelist and blacklist from files
        readWhitelist(whitelistSet);
        readBlacklist(blacklistSet);

        //Analyze url and print risk assessment
        URLResult result = URLChecker.analyze(url, whitelistSet, blacklistSet);
        result.print();

        scan.close(); //close scanner to avoid resource leak
    }


    //Read whitelist from file
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

    //Read blacklist from file
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