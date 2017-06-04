import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

/**
 * Created by appie on 4-6-2017.
 */
public class TerminalApplication extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("TerminalLayout.fxml"));
        primaryStage.setTitle("Terminal");
        primaryStage.setScene(new Scene(root, 750, 600));
        primaryStage.show();
    }

}
