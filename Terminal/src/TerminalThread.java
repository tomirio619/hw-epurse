import javacard.framework.ISO7816;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;


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
    private final static byte PERSONALIZATION_HI = (byte) 0x30;
    private final static byte PERSONALIZATION_DATES = (byte) 0x31;

    private final static byte VERIFICATION_V = (byte) 0x42;
    private final static byte VERIFICATION_S = (byte) 0x47;

    private final static byte BACKEND_KEY = (byte) 0x46;





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

                            testSignatureRSA(ch);

                            //testPersonalizationHi(ch);
                            //testPesonalizationDates(ch);
                            //testPin(ch);

                            testTerminalAuth(ch);

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

    // the key components and the signature dont fit in an apdu, the idea is send this component
    // firts and then signature of both, modulus and exponent
    public void testTerminalAuth(CardChannel ch) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, CardException {

        //First generate test terminal keypair
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "BC");
        g.initialize(1024, new SecureRandom());
        java.security.KeyPair pairT = g.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) pairT.getPublic();
        byte[] exponentBytes = getBytes(publicKey.getPublicExponent());
        byte[] modulusBytes = getBytes(publicKey.getModulus());

        //Generate BE keys
        g.initialize(1024, new SecureRandom());
        java.security.KeyPair pairB = g.generateKeyPair();
        RSAPrivateKey privateKeyBE = (RSAPrivateKey) pairB.getPrivate();
        RSAPublicKey publicKeyBE = (RSAPublicKey) pairB.getPublic();

        //Sign the public key of the terminal
        byte[] bytesKeyTerm = new byte [modulusBytes.length+exponentBytes.length];
        Util.arrayCopy(modulusBytes,(short)0,bytesKeyTerm,(short)0,(short)modulusBytes.length);
        Util.arrayCopy(exponentBytes,(short)0,bytesKeyTerm,(short)modulusBytes.length,(short)exponentBytes.length);

        // This is the signature of the BackEnd
        byte[] signedKeyTerm = null;
        try {
            Signature signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initSign(privateKeyBE);
            signature.update(bytesKeyTerm,0,bytesKeyTerm.length);
            signedKeyTerm = signature.sign();
            int lenghtSig = signedKeyTerm.length;

        }catch (Exception e){
            e.printStackTrace();
        }

        // Send BE key for verify signatures(this will be done in the personalization)
        byte[] exponentBytesBE = getBytes(publicKeyBE.getPublicExponent());
        byte[] modulusBytesBE = getBytes(publicKeyBE.getModulus());
        byte[] bytesKeyBE = new byte [modulusBytesBE.length+exponentBytesBE.length];
        Util.arrayCopy(exponentBytesBE,(short)0,bytesKeyBE,(short)0,(short)exponentBytesBE.length);
        Util.arrayCopy(modulusBytesBE,(short)0,bytesKeyBE,(short)exponentBytesBE.length,(short)modulusBytesBE.length);
        CommandAPDU capdu;
        capdu = new CommandAPDU(CLASS, BACKEND_KEY, (byte) exponentBytesBE.length, (byte) modulusBytesBE.length, bytesKeyBE);
        ResponseAPDU responsePrivate = ch.transmit(capdu);
        System.out.println("BACKEND_KEY: " + Integer.toHexString(responsePrivate.getSW()));

        // Send public key of the terminal
        capdu = new CommandAPDU(CLASS, VERIFICATION_V, (byte) exponentBytesBE.length, (byte) modulusBytesBE.length, bytesKeyTerm);
        responsePrivate = ch.transmit(capdu);
        System.out.println("VERIFICATION_V: " + Integer.toHexString(responsePrivate.getSW()));

        // Send public key of the terminal signed
        capdu = new CommandAPDU(CLASS, VERIFICATION_S, (byte) 0, (byte) 0, signedKeyTerm);
        responsePrivate = ch.transmit(capdu);
        System.out.println("VERIFICATION_S: " + Integer.toHexString(responsePrivate.getSW()));
    }

    private void testSignatureRSA(CardChannel ch) {

        System.out.println("-----Test signature RSA-----");


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
            System.out.println("SEND_KEYPAIR modulus: " + Integer.toHexString(responsePrivate.getSW()));


            byte[] exponent = getBytes(privatekey.getPrivateExponent());
            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 1, (byte) 0, exponent);
            responsePrivate = ch.transmit(capdu);
            System.out.println("SEND_KEYPAIR exponent: " + Integer.toHexString(responsePrivate.getSW()));

            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR, (byte) 0, (byte) 0, 0);
            responsePrivate = ch.transmit(capdu);
            System.out.println("SIGNING Request: " + Integer.toHexString(responsePrivate.getSW()));

            byte[] data = {(byte) 42};

            try {
                byte[] signedDataTerminal = responsePrivate.getData();
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initVerify(publickey);
                signature.update(signedDataTerminal[0]);
                boolean ifVerified = signature.verify(signedDataTerminal, (short) 1, (short) 128);
                System.out.println("Verification " +ifVerified);
            }catch (Exception e){
                e.printStackTrace();
            }


        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    public void testPersonalizationHi(CardChannel ch) throws CardException, NoSuchAlgorithmException {
        System.out.println("-----Test Personalization Hi-----");

        KeyPairGenerator generator  = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair keypair = generator.generateKeyPair();
        RSAPublicKey cardPublickey = (RSAPublicKey) keypair.getPublic();
        RSAPrivateKey cardPrivateKey = (RSAPrivateKey) keypair.getPrivate();

        //byte [] nonceBytes = new byte[2];
        //secureRandom.nextBytes(nonceBytes);

        byte[] modulus = getBytes(cardPrivateKey.getModulus());
        // Sending modulus private key
        CommandAPDU capdu;
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 0, (byte) 0, modulus);
        ResponseAPDU responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_HI private modulus: " + Integer.toHexString(responsePrivate.getSW()));

        // Sending exponent private key
        byte[] exponent = getBytes(cardPrivateKey.getPrivateExponent());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 1, (byte) 0, exponent);
        responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_HI private exponent: " + Integer.toHexString(responsePrivate.getSW()));

        modulus = getBytes(cardPublickey.getModulus());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 2, (byte) 0, modulus);
        responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_HI public modulus: " + Integer.toHexString(responsePrivate.getSW()));

        exponent = getBytes(cardPublickey.getPublicExponent());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 3, (byte) 0, exponent);
        responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_HI public exponent: " + Integer.toHexString(responsePrivate.getSW()));


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

    private void testPesonalizationDates(CardChannel ch) throws CardException {

        System.out.println("-----Test Personalization Dates-----");

        // Get current date unix seconds
        int unixTime = (int)(System.currentTimeMillis() / 1000);
        byte[] personalizedDate = new byte[]{
                (byte) (unixTime >> 24),
                (byte) (unixTime >> 16),
                (byte) (unixTime >> 8),
                (byte) unixTime

        };// convert date to byte array

        // Create a random card ID
        short randId = (short) ((double) 10000 * Math.random());
        byte[] id = new byte[]{
                (byte) (randId >> 8),
                (byte) randId

        };

        short idUnido = Util.makeShort(id[0], id[1]);
        // TODO check unique ID = " SELECT COUNT(*) as CN FROM CARD WHERE CARDID= (?)";

        byte[] dataToSend = new byte[6];//container of data that will be sent to the card

        Util.arrayCopy(id, (short)0, dataToSend, (short)0, (short)2); //copy card id to container
        Util.arrayCopy(personalizedDate, (short)0, dataToSend, (short)2, (short)4);//copy date to container
        //send data to the card
        CommandAPDU capdu;
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_DATES, (byte) 0, (byte) 0, dataToSend);
        ResponseAPDU responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_DATES: " + Integer.toHexString(responsePrivate.getSW()));

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
