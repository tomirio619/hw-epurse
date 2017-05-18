import javacard.framework.ISO7816;

import javacard.framework.Util;
import javacard.security.*;
import javacard.security.Key;
import javacard.security.Signature;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyPair;
//import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.DataTruncation;
import java.util.List;

/*import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyPair;
import javacard.security.Signature;*/


import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertTrue;


/**
 * Created by Tomirio on 9-5-2017.
 */
public class TerminalThread implements Runnable {

    private static final String APPLET_AID = "a04041424344454610"; //01";
    private static final byte CLASS = (byte) 0xB0;
    private final static byte VERIFICATION_HI = (byte) 0x41;
    private final static byte SEND_KEYPAIR = (byte) 0x43;
    private final static byte SEND_KEYPAIR_RSA = (byte) 0x45;



    @Override
    public void run() {
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


            TerminalFactory tf = TerminalFactory.getDefault();
            CardTerminals ct = tf.terminals();
            List<CardTerminal> cs = ct.list(CardTerminals.State.ALL);//CardTerminals.State.CARD_PRESENT);
            if (cs.isEmpty()) {
                System.err.println("No terminals with a card found.");
                return;
            }
            for (CardTerminal c : cs) {
                if (c.isCardPresent()) {
                    System.out.println("We are communicating with the following card terminal: " + c.getName());
                    System.out.println("The card is present!");
                    try {
                        Card card = c.connect("*");
                        try {
                            CardChannel ch = card.getBasicChannel();
                            System.out.println(DatatypeConverter.printHexBinary(Hex.decode(APPLET_AID)));
                            CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(APPLET_AID));
                            ResponseAPDU response = ch.transmit(selectApplet);
                            System.out.println(DatatypeConverter.printHexBinary(selectApplet.getBytes()));
                            System.out.println(DatatypeConverter.printHexBinary(response.getBytes()));

                            //testSignature(ch);

                            testSignatureRSA(ch);
                            //1. Terminal sends Hi
//                            byte[] payload = new byte[2];
//                            new SecureRandom().nextBytes(payload);
//                            short random = Util.makeShort(payload[0], payload[1]);
//                            random = (short) Math.abs(random);
//                            System.out.println(random);
//
//                            CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, payload, 2);
//                            ResponseAPDU responseHi = ch.transmit(hiAPDU);
//                            byte[] randomInc = responseHi.getData();
//                            short incremented = Util.makeShort(randomInc[0], randomInc[1]);
//                            System.out.println(incremented);

                        } catch (Exception e) {
                        }
                        card.disconnect(false);

                    } catch (CardException e) {
                        System.err.println("Couldn't connect to card!");
                    }
                    return;

                } else {
                    System.err.println("No card present!");
                }
            }
        } catch (CardException e) {
            System.err.println("Card status problem!");
        }
    }

    private void testSignatureRSA(CardChannel ch) {

        RSAPublicKey publickey = null;

        RSAPrivateKey privatekey = null;

        /* Generate keypair. */
        try {
            System.out.println("Generating keys...");
            KeyPairGenerator generator = null;

            generator = KeyPairGenerator.getInstance("RSA");

            generator.initialize(1024);
            KeyPair keypair = generator.generateKeyPair();
            publickey = (RSAPublicKey) keypair.getPublic();
            privatekey = (RSAPrivateKey) keypair.getPrivate();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        /* Send private key. */
        try {
            //byte[] data = readFile();
            //X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            //KeyFactory factory = KeyFactory.getInstance("RSA");
            //RSAPublicKey key = (RSAPublicKey) factory.generatePublic(spec);


            byte[] modulus = getBytes(privatekey.getModulus());

            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 0, (byte) 0, modulus);
            ResponseAPDU responsePrivate = ch.transmit(capdu);
            System.out.println("SEND_KEYPAIR modulus: "+responsePrivate.getSW());


            byte[] exponent = getBytes(privatekey.getPrivateExponent());
            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 1, (byte) 0, exponent);
            responsePrivate = ch.transmit(capdu);
            System.out.println("SEND_KEYPAIR exponent: "+responsePrivate.getSW());


        } catch (Exception e) {

        }

        Signature signingKey = javacard.security.Signature.getInstance(javacard.security.Signature.ALG_RSA_SHA_PKCS1, false);
        signingKey.init((Key) privatekey, javacard.security.Signature.MODE_SIGN);

    }

    public void testSignature(CardChannel ch) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, CardException {
        //First generate a signing keypair
        System.err.println("Test Signature");


        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("prime192v1");
        KeyPairGenerator g = null;
        try {
            g = KeyPairGenerator.getInstance("EC", "BC");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        g.initialize(ecGenParameterSpec, new SecureRandom());
        java.security.KeyPair pair = g.generateKeyPair();
        java.security.interfaces.ECPrivateKey privateKey = (java.security.interfaces.ECPrivateKey) pair.getPrivate();
        java.security.interfaces.ECPublicKey publicKey = (java.security.interfaces.ECPublicKey) pair.getPublic();

        //Send the S part to the card
        byte[] privateKeyArray = privateKey.getS().toByteArray();

        CommandAPDU sendKeyPairAPDU = new CommandAPDU(CLASS, SEND_KEYPAIR, 0, 0, privateKeyArray, privateKeyArray.length);
        ResponseAPDU responsePrivate = ch.transmit(sendKeyPairAPDU);

        //The card sends a signature check on the message 42
        byte[] signatureData = responsePrivate.getData();
        Signature signature = null;
        try {
            signature = Signature.getInstance("EC", "BC");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        signature.initVerify(publicKey);
        signature.update((byte) 42);
        //Lets check it
        assertTrue(signature.verify(signatureData, 1, signatureData.length - 1));

        //Check whether it fails with a wrong message
        signature.update((byte) 41);
        assertFalse(signature.verify(signatureData, 1, signatureData.length - 1));

        //Or with a wrong key
        signature.initVerify(g.generateKeyPair().getPublic());
        signature.update((byte) 42);
        assertFalse(signature.verify(signatureData, 1, signatureData.length - 1));
    }


    /**
     * Gets an unsigned byte array representation of <code>big</code>. A leading
     * zero (present only to hold sign bit) is stripped.
     *
     * @param big
     *            a big integer.
     *
     * @return a byte array containing a representation of <code>big</code>.
     */
    byte[] getBytes(BigInteger big) {
        byte[] data = big.toByteArray();
        if (data[0] == 0) {
            byte[] tmp = data;
            data = new byte[tmp.length - 1];
            System.arraycopy(tmp, 1, data, 0, tmp.length - 1);
        }
        return data;
    }


}
