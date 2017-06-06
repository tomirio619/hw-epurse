import Events.CardConnectedEvent;
import Events.UpdateLogsEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;

import javax.smartcardio.CardException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by appie on 4-6-2017.
 */
public class TerminalController implements Initializable, Observer {

    @FXML
    private TextField reloadAmount;

    @FXML
    private TextArea txtDebug;

    @FXML
    private Label txtConnection;

    private Terminal terminal;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        System.out.println("Am I first?");
        terminal = new Terminal();

        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                updateDebug("Hallo");
            }
        }, 0, 1000);
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

    private void updateDebug(String message){
        SimpleDateFormat format = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        Date date = new Date();
        String dateFormatted = format.format(date);

        txtDebug.appendText(dateFormatted + ": " + message + "\n");
    }

    private void startVerification(){
        try {
            terminal.testPersonalizationHi();
        } catch (CardException | NoSuchAlgorithmException | NullPointerException e) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setHeaderText("Error");
            alert.setContentText(e.getMessage());
            alert.showAndWait();
        }
    }


    @Override
    public void update(Observable o, Object arg) {
        if (arg instanceof UpdateLogsEvent){
            updateDebug(((UpdateLogsEvent) arg).getLog());
        }

        if (arg instanceof CardConnectedEvent){
            txtConnection.setText(((CardConnectedEvent) arg).getCardName());
        }
    }
}
