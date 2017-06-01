import javacard.framework.ISO7816;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;



/**
 * Created by Tomirio on 9-5-2017.
 */
public class Terminal {


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
    private final static byte DECOMMISSIONING_HI = (byte) 0x33;
    private final static byte DECOMMISSIONING_CLEAR = (byte) 0x34;


    private RSAPublicKey publicKeyBackend;
    private RSAPrivateKey privateKeyBackend;

    private RSAPublicKey publicKeyTerminal;
    private RSAPrivateKey privateKeyTerminal;

    private SecureRandom secureRandom;


    public Terminal() {
        loadBackendKeys();
        loadTerminalKeys();
        secureRandom = new SecureRandom();
        (new TerminalThread()).start();
    }



    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Terminal terminal = new Terminal();
    }

    void loadBackendKeys()   {



        // Load the key into BigIntegers
        BigInteger modulus = new BigInteger(BackendKeys.privateModulusBackend, 16);
        BigInteger exponent = new BigInteger(BackendKeys.privateExponentBackend, 16);
        BigInteger pubExponent = new BigInteger(BackendKeys.publicExponentBackend);

        // Create private and public key specs
        RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, exponent);
        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubExponent);

        // Create a key factory
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
            // Create the RSA private and public keys
            privateKeyBackend = (RSAPrivateKey) factory.generatePrivate(privateSpec);
            publicKeyBackend = (RSAPublicKey) factory.generatePublic(publicSpec);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }


    }

    private void loadTerminalKeys() {
        //First generate test terminal keypair
        KeyPairGenerator g = null;
        try {
            g = KeyPairGenerator.getInstance("RSA", "BC");
            g.initialize(1024, new SecureRandom());
            java.security.KeyPair pairT = g.generateKeyPair();
            publicKeyTerminal = (RSAPublicKey) pairT.getPublic();
            privateKeyTerminal = (RSAPrivateKey) pairT.getPrivate();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

    }


    class TerminalThread extends Thread  {

        @Override
        public void run() {
            try {



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

                                personalizationFull(ch);

                                testTerminalAuth(ch);

                                testDecommissioning(ch);
                                //testSignatureRSA(ch);



                                //testTerminalAuth(ch);

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


        // Send all step personalization
        private void personalizationFull(CardChannel ch) throws CardException, NoSuchAlgorithmException {

            System.out.println("-----Test Personalization-----");
            testSendBackendKey(ch);
            testPersonalizationHi(ch);
            testPesonalizationDates(ch);
            testPin(ch);
        }

        // the key components and the signature dont fit in an apdu, the idea is send this component
        // firts and then signature of both, modulus and exponent
        public void testTerminalAuth(CardChannel ch) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, CardException {

            System.out.println("-----Test Verification Terminal-----");

            byte [] nonceBytes = new byte[2];
            secureRandom.nextBytes(nonceBytes);
            CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, nonceBytes, 2);
            ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
            System.out.println("VERIFICATION_HI: " + Integer.toHexString(responseAPDU.getSW()));


            //Sign the public key of the terminal
            byte[] exponentBytes = getBytes(publicKeyTerminal.getPublicExponent());
            byte[] modulusBytes = getBytes(publicKeyTerminal.getModulus());
            byte[] bytesKeyTerm = new byte [modulusBytes.length+exponentBytes.length];
            Util.arrayCopy(exponentBytes,(short)0,bytesKeyTerm,(short)0,(short)exponentBytes.length);
            Util.arrayCopy(modulusBytes,(short)0,bytesKeyTerm,(short)exponentBytes.length,(short)modulusBytes.length);

            // This is the signature of the BackEnd
            byte[] signedKeyTerm = null;
            int lenghtSig=0;
            try {
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(privateKeyBackend);
                signature.update(bytesKeyTerm,0,bytesKeyTerm.length);
                signedKeyTerm = signature.sign();
                lenghtSig = signedKeyTerm.length;

            }catch (Exception e){
                e.printStackTrace();
            }


            CommandAPDU capdu;
            ResponseAPDU responsePrivate;

            // Send public key of the terminal
            capdu = new CommandAPDU(CLASS, VERIFICATION_V, (byte) exponentBytes.length, (byte) modulusBytes.length, bytesKeyTerm);
            responsePrivate = ch.transmit(capdu);
            System.out.println("VERIFICATION_V: " + Integer.toHexString(responsePrivate.getSW()));

            // Send public key of the terminal signed
            capdu = new CommandAPDU(CLASS, VERIFICATION_S, (byte) 0, (byte) 0, signedKeyTerm);
            responsePrivate = ch.transmit(capdu);
            System.out.println("VERIFICATION_S: " + Integer.toHexString(responsePrivate.getSW()));
        }



        public void testSendBackendKey(CardChannel ch) throws CardException {
            // Send BE key for verify signatures(this will be done in the personalization)
            byte[] exponentBytesBE = getBytes(publicKeyBackend.getPublicExponent());
            byte[] modulusBytesBE = getBytes(publicKeyBackend.getModulus());
            byte[] bytesKeyBE = new byte [modulusBytesBE.length+exponentBytesBE.length];
            Util.arrayCopy(exponentBytesBE,(short)0,bytesKeyBE,(short)0,(short)exponentBytesBE.length);
            Util.arrayCopy(modulusBytesBE,(short)0,bytesKeyBE,(short)exponentBytesBE.length,(short)modulusBytesBE.length);
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, BACKEND_KEY, (byte) exponentBytesBE.length, (byte) modulusBytesBE.length, bytesKeyBE);
            ResponseAPDU responsePrivate = ch.transmit(capdu);
            System.out.println("BACKEND_KEY: " + Integer.toHexString(responsePrivate.getSW()));

        }

        public void testPersonalizationHi(CardChannel ch) throws CardException, NoSuchAlgorithmException {
            KeyPairGenerator generator  = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            java.security.KeyPair keypair = generator.generateKeyPair();
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

        private void testPesonalizationDates(CardChannel ch) throws CardException {

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

        private void testPin(CardChannel ch) {

            byte[] pin = {1, 2, 3, 4};
            try {
                CommandAPDU capdu;
                capdu = new CommandAPDU(CLASS, PERSONALIZATION_NEW_PIN, (byte) 0, (byte) 0, pin);
                ResponseAPDU responsePrivate = ch.transmit(capdu);
                System.out.println("Set pin: " + Integer.toHexString(responsePrivate.getSW()));

                //capdu = new CommandAPDU(CLASS, CREDIT_COMMIT_PIN, (byte) 0, (byte) 0, pin);
                //responsePrivate = ch.transmit(capdu);
                //System.out.println("Check pin: " + Integer.toHexString(responsePrivate.getSW()));

            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        private void testDecommissioning(CardChannel ch) throws CardException {
            System.out.println("-----Test Decommissioning-----");

            byte [] nonceBytes = new byte[2];
            secureRandom.nextBytes(nonceBytes);
            short firstShort = Util.makeShort(nonceBytes[0], nonceBytes[1]);

            // This is the signature of the Terminal
            byte[] signedNonce = null;
            try {
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(privateKeyTerminal);
                signature.update(nonceBytes,0,nonceBytes.length);
                signedNonce = signature.sign();

            }catch (Exception e){
                e.printStackTrace();
            }
            byte[] combinedData = new byte[nonceBytes.length + signedNonce.length];

            System.arraycopy(nonceBytes,0,combinedData,0         ,nonceBytes.length);
            System.arraycopy(signedNonce,0,combinedData,nonceBytes.length,signedNonce.length);


            CommandAPDU hiAPDU = new CommandAPDU(CLASS, DECOMMISSIONING_HI, 0, 0, combinedData, combinedData.length);
            ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
            System.out.println("DECOMMISSIONING_HI: " + Integer.toHexString(responseAPDU.getSW()));

            //TODO verify signature, send info backend
            byte [] dataRec = responseAPDU.getData();
            short nonce = Util.makeShort(dataRec[0], dataRec[1]);
            nonce = (short) (nonce+1);
            short id = Util.makeShort(dataRec[2], dataRec[3]);

            byte [] dataToSend = new byte[]{
                    (byte) (nonce >> 8),
                    (byte) nonce

            };

            hiAPDU = new CommandAPDU(CLASS, DECOMMISSIONING_CLEAR, 0, 0, dataToSend, dataToSend.length);
            responseAPDU = ch.transmit(hiAPDU);
            System.out.println("DECOMMISSIONING_CLEAR: " + Integer.toHexString(responseAPDU.getSW()));



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
                java.security.KeyPair keypair = generator.generateKeyPair();
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


    }
}
