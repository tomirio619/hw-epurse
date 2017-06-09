/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author root
 */
public class Channel {

    private SocketAddress sA;
    private ServerSocket serverSocket;
    private Socket socket;
    private Database db;


    public Channel(int port, Database db) {
        this.db = db;
        try {
            sA = new InetSocketAddress(InetAddress.getByName(null), port);
            serverSocket = new ServerSocket(port);
        } catch (Exception ex) {
            Logger.getLogger(Channel.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void startListening() {
        try {
            while (true) {
                socket = serverSocket.accept();
                try {

                    DataInputStream dIn = new DataInputStream(socket.getInputStream());

                    int length = dIn.readInt();                    // read length of incoming message
                    if (length > 0) {
                        byte[] message = new byte[length];
                        dIn.readFully(message, 0, message.length); // read the message
                        MessageHandler mh = new MessageHandler(this, message, db);
                    }

                } finally {
                    socket.close();
                }
            }
        } catch (Exception ex) {
            Logger.getLogger(Channel.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                serverSocket.close();
            } catch (IOException ex) {
                Logger.getLogger(Channel.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

    }

    public void sendMessage(byte[] message) {
        try {
            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
            dOut.writeInt(message.length); // write length of the message
            dOut.write(message);           // write the message
        } catch (IOException ex) {
            Logger.getLogger(Channel.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
