/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.security.Security;

/**
 * @author root
 */
public class EPurseBankBackend {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Database db = new Database();
        Channel ch = new Channel(9090, db);
        ch.startListening();
        db.disconnect();
    }

}
