import java.util.Scanner;

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

        URLResult result = URLChecker.analyze(url);
        result.print();

        
    }
}