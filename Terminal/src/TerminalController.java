import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;

import java.net.URL;
import java.text.ParseException;
import java.util.ResourceBundle;

/**
 * Created by appie on 4-6-2017.
 */
public class TerminalController implements Initializable{

    @FXML
    private TextField reloadAmount;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        System.out.println("Am I first?");
        Terminal t = new Terminal();
    }

    @FXML
    private void startPersonalization(){
        System.out.println("Hallo");
    }

    private boolean isADouble(TextField field){
        try{
            String text = field.getText();
            Double.parseDouble(text);
        }catch(NumberFormatException nfe){
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Parse error");
            alert.setContentText("Please check your amount, since this is not a valid number");
            field.clear();
            alert.showAndWait();
            return false;
        }
        return true;
    }

    @FXML
    private void startReload(){
        if (isADouble(reloadAmount)){
            System.out.println("Reload");
        }else{
            System.out.println("No!");
        }
    }




}
