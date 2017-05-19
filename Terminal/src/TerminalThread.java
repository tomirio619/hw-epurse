import com.sun.prism.PixelFormat;
import javacard.framework.ISO7816;
import javacard.security.*;
import javacard.security.Signature;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import ePurse.Epurse;


/**
 * Created by Tomirio on 9-5-2017.
 */
public class TerminalThread implements Runnable {

    private static final String APPLET_AID = "a04041424344454610"; //01";
    private static final byte CLASS = (byte) 0xB0;
    private final static byte VERIFICATION_HI = (byte) 0x41;
    private final static byte SEND_KEYPAIR = (byte) 0x43;
    private final static byte SEND_KEYPAIR_RSA = (byte) 0x45;
    private final static byte PERSONALIZATION_NEW_PIN = (byte) 0x32;
    private final static byte CREDIT_COMMIT_PIN = (byte) 0x38;


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
                            testPin(ch);
                            //testSignatureRSA(ch);
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
            byte[] modulus = getBytes(privatekey.getModulus());

            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 0, (byte) 0, modulus);
            ResponseAPDU responsePrivate = ch.transmit(capdu);
            System.out.println("SEND_KEYPAIR modulus: " + responsePrivate.getSW());


            byte[] exponent = getBytes(privatekey.getPrivateExponent());
            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 1, (byte) 0, exponent);
            responsePrivate = ch.transmit(capdu);
            System.out.println("SEND_KEYPAIR exponent: " + responsePrivate.getSW());

            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR, (byte) 0, (byte) 0, 0);
            responsePrivate = ch.transmit(capdu);
            System.out.println("SIGNING Request: " + responsePrivate.getSW());

            byte[] data = {(byte) 42};
            javacard.security.Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

            javacard.security.RSAPublicKey pkey = (javacard.security.RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
            pkey.setExponent(publickey.getPublicExponent().toByteArray(), (short) 0, (short) publickey.getPublicExponent().toByteArray().length);
            pkey.setModulus(publickey.getModulus().toByteArray(), (short) 0, (short) publickey.getModulus().toByteArray().length);

            signature.init(pkey, Signature.MODE_VERIFY);
            System.out.println(DatatypeConverter.printHexBinary(responsePrivate.getData()));
            boolean correct = signature.verify(responsePrivate.getData(), (short) 0, (short) 1, responsePrivate.getData(), (short) 1, (short) (responsePrivate.getData().length - 1));
            System.out.println(correct);

        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    private void testPin(CardChannel ch) {

        byte[] pin = {1, 2, 3, 4};
        try {
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, PERSONALIZATION_NEW_PIN, (byte) 0, (byte) 0, pin);
            ResponseAPDU responsePrivate = ch.transmit(capdu);
            System.out.println("Set pin: " + Integer.toHexString(responsePrivate.getSW()));

            capdu = new CommandAPDU(CLASS, CREDIT_COMMIT_PIN, (byte) 0, (byte) 0, pin);
            responsePrivate = ch.transmit(capdu);
            System.out.println("Check pin: " + Integer.toHexString(responsePrivate.getSW()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Gets an unsigned byte array representation of <code>big</code>. A leading
     * zero (present only to hold sign bit) is stripped.
     *
     * @param big a big integer.
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
