import Events.ErrorEvent;
import Events.IObservable;
import javafx.scene.control.Alert;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

/**
 * Created by appie on 4-6-2017.
 */
public class BackEndCommunicator extends Thread implements IObservable{

    private Socket socket;
    private List<Observer> observers;

    public BackEndCommunicator() {
    }

    @Override
    public synchronized void addObserver(Observer o) {
        if (observers == null){
            observers = new ArrayList<>();
        }
        observers.add(o);
    }

    @Override
    public void update(Object event) {
        if (observers == null){
            return;
        }
        for (Observer o : observers){
            o.update(null, event);
        }
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
                if (length == 4){
                    //Handle the exception
                    buffer = new byte[length];
                    dIn.read(buffer, 0, length); //Read the error

                    //Convert to integer
                    int errorCode = ByteBuffer.wrap(buffer).getInt();
                    System.out.println("Errorcode " + errorCode);
                    switch (errorCode){
                        case 3:
                            //Signature is not valid
                            this.update(new ErrorEvent("Signature is not valid"));
                            break;
                    }
//                    this.update(new ErrorEvent());
                    break;
                }

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
