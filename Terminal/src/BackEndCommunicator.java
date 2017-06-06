import javafx.scene.control.Alert;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
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
            socket = new Socket("127.0.0.1", 9090);
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
    public byte[] sendAndReceive(byte[] data) {
        try {
            System.out.println("Sending data of length " + data.length);
            System.out.println(DatatypeConverter.printHexBinary(data));
            DataOutputStream dOut = new DataOutputStream(outToServer);
            dOut.writeInt(data.length);
            dOut.write(data);

            DataInputStream dIn = new DataInputStream(inFromServer);

            int count;
            byte[] buffer = new byte[8192]; // or 4096, or more
            while ((count = dIn.read(buffer)) > 0)
            {
                dOut.write(buffer, 0, count);
            }

            return buffer;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }



}
