import javafx.scene.control.Alert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Created by appie on 4-6-2017.
 */
public class BackEndCommunicator extends Thread{

    private Socket socket;
    private OutputStream outToServer;
    private InputStream inFromServer;

    public BackEndCommunicator() {
        setUp();
    }

    private void setUp(){
        try {
            socket = new Socket("127.0.0.1", 76395);
            outToServer = socket.getOutputStream();
            inFromServer = socket.getInputStream();
        } catch (IOException e) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Socket connection error");
            alert.setContentText("Unable to connect to specified host/socket");
            alert.showAndWait();
        }
    }

    /**
     * Send data to the backend and wait for the response
     * @param data
     * @return
     */
    private byte[] sendAndReceive(byte[] data) throws IOException {
        outToServer.write(data);
        return null;
    }



}
