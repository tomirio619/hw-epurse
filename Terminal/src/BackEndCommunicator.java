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
//        try {
//            socket = new Socket("127.0.0.1", 9090);
//            outToServer = socket.getOutputStream();
//            inFromServer = socket.getInputStream();
//        } catch (IOException e) {
//            Alert alert = new Alert(Alert.AlertType.ERROR);
//            alert.setTitle("Socket connection error");
//            alert.setContentText("Unable to connect to specified host/socket");
//            alert.showAndWait();
//        }
    }

    /**
     * Send data to the backend and wait for the response
     * @param data
     * @return
     */
    public byte[] sendAndReceive(byte[] data) {
        try {
            socket = new Socket("127.0.0.1", 9090);
            System.out.println("Sending data of length " + data.length);
            System.out.println("About to send " + DatatypeConverter.printHexBinary(data));
            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
            dOut.writeInt(data.length);
            dOut.write(data);

            DataInputStream dIn;
            byte[] buffer = null;
            while(true){
                dIn = new DataInputStream(socket.getInputStream());

                int length = dIn.readInt();
                if (length > 0){
                    buffer = new byte[length];
                    dIn.readFully(buffer, 0, length);
                    break;
                }
            }

            dOut.close();
            dIn.close();
            socket.close();
            return buffer;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }



}
