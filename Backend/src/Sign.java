/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Sign {


    public static byte[] createSignature(RSAPrivateKey secKey, byte[] message) {
        byte[] sig = {};
        try {
            if (secKey != null) {
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(secKey);
                signature.update(message);
                byte[] sigBytes = signature.sign();
                sig = sigBytes;
            }
        } catch (Exception ex) {
            Logger.getLogger(Sign.class.getName()).log(Level.SEVERE, null, ex);
        }
        return sig;
    }

    public static boolean checkSignature(byte[] message, byte[] sig, RSAPublicKey pubKey) {
        Signature signature;
        try {
            if (pubKey != null) {
                signature = Signature.getInstance("SHA1withRSA", "BC");
                byte[] sigBytes = sig;
                signature.initVerify(pubKey);
                signature.update(message);
                return signature.verify(sigBytes);
            }
        } catch (Exception ex) {
            Logger.getLogger(Sign.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

}
