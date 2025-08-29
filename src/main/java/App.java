import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

public class App extends Application { //allows you to get the functionality for a JavaFX application
    public static void main (String args[]) {
        launch(args); //sets up the application you are trying to make
    }

    @Override
    public void start (Stage primaryStage) throws Exception {
        //window = stage
        //everything inside your window = scene
        primaryStage.setTitle("Phishing URL Checker");
        Button button = new Button();
        button.setText("Check!"); //makes and initializes the button
    }
}