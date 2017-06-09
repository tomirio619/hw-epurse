import javacard.framework.ISO7816;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


/**
 * Created by Tomirio on 9-5-2017.
 */
public class Terminal extends Thread {

    private static final String APPLET_AID = "a04041424344454610"; //01";
    private static final byte CLASS = (byte) 0xB0;
    private final static byte VERIFICATION_HI = (byte) 0x41;
    private final static byte SEND_KEYPAIR = (byte) 0x43;
    private final static byte SEND_KEYPAIR_RSA = (byte) 0x45;
    private final static byte PERSONALIZATION_NEW_PIN = (byte) 0x32;
    private final static byte PERSONALIZATION_HI = (byte) 0x30;
    private final static byte PERSONALIZATION_DATES = (byte) 0x31;
    private final static byte VERIFICATION_V = (byte) 0x42;
    private final static byte VERIFICATION_S = (byte) 0x47;
    private final static byte PERSONALIZATION_BACKEND_KEY = (byte) 0x20;
    private final static byte DECOMMISSIONING_HI = (byte) 0x33;
    private final static byte DECOMMISSIONING_CLEAR = (byte) 0x34;

    private final static byte RELOADING_HI = (byte) 0x35;
    private final static byte RELOADING_UPDATE = (byte) 0x36;

    private final static byte CREDIT_HI = (byte) 0x37;
    private final static byte CREDIT_COMMIT_PIN = (byte) 0x38;
    private final static byte CREDIT_COMMIT_NO_PIN = (byte) 0x39;
    private final static byte CREDIT_NEW_BALANCE = (byte) 0x40;


    private RSAPublicKey publicKeyBackend;
    private RSAPrivateKey privateKeyBackend;

    private RSAPublicKey publicKeyTerminal;
    private RSAPrivateKey privateKeyTerminal;
    private RSAPrivateKey privateKeyCard;

    private SecureRandom secureRandom;
    private byte[] terminalId = new byte[]{0x00, 0x01};

    private RSAPublicKey publicKeyCard;

    private RSAPublicKey tempCardPublicKey;

    private BackEndCommunicator backend;
    private CardChannel ch = null;

    private List<Observer> observers;


    public Terminal(BackEndCommunicator be) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        loadBackendKeys();
        loadTerminalKeys();
        secureRandom = new SecureRandom();
        this.backend = be;

        this.start();
    }

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
                            ch = card.getBasicChannel();
                            System.out.println(DatatypeConverter.printHexBinary(Hex.decode(APPLET_AID)));
                            CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(APPLET_AID));
                            ResponseAPDU response = ch.transmit(selectApplet);
                            System.out.println(DatatypeConverter.printHexBinary(selectApplet.getBytes()));
                            System.out.println(DatatypeConverter.printHexBinary(response.getBytes()));

//                            personalizationFull();

                            testTerminalAuth();

                            testReloading((short) 500);

                            testCrediting();
//
//                            testDecommissioning();

                        } catch (Exception e) {
                            e.printStackTrace();
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
            System.out.println(publicKeyBackend.getPublicExponent());
            System.out.println(publicKeyBackend.getModulus());

            System.out.println(privateKeyBackend.getPrivateExponent());
            System.out.println(privateKeyBackend.getModulus());


        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    // Type 0 public 1 private
    private RSAKey keyFromEncoded(byte[] encodedKey, int type){
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            if(type == 0){
                return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedKey));
            }else{
                return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new X509EncodedKeySpec(encodedKey));
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            System.out.println(ex.getStackTrace());
            //Logger.getLogger(MessageHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }



    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)+Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Loads the terminal key
     */
    private void loadTerminalKeys() {
        //First generate test terminal keypair
        BigInteger modulus = new BigInteger(TerminalKeys.modulus, 16);
        BigInteger exponent = new BigInteger(TerminalKeys.privateExponent, 16);

        // Create private  key specs
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, exponent);

        // Create a key factory
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
            // Create the RSA private and public keys
            privateKeyTerminal = (RSAPrivateKey) factory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        publicKeyTerminal = (RSAPublicKey) keyFromEncoded(hexStringToByteArray(TerminalKeys.publicEncoded), 0);
    }

    // Send all step personalization
    public void personalizationFull() throws CardException, NoSuchAlgorithmException {
        System.out.println("-----Test Personalization-----");
        testSendBackendKey();
        testPersonalizationHi();
        testPesonalizationDates();
        testPin();
    }

    /**
     * Checks whether a nonce (oldNonce1 || oldNonce2) + incrementedBy == nonce (newNonce1 || newNonce2)
     * @param oldNonce1
     * @param oldNonce2
     * @param newNonce1
     * @param newNonce2
     * @param incrementedBy
     * @return
     */
    private boolean isNonceIncrementedBy(byte oldNonce1, byte oldNonce2, byte newNonce1, byte newNonce2, int incrementedBy){
        short old = Util.makeShort(oldNonce1, oldNonce2);
        short newNonce = Util.makeShort(newNonce1, newNonce2);

        return old + incrementedBy == newNonce;
    }

    /**
     * Sign a byte array with the key of the terminal
     * @param textToSign
     * @return
     */
    private byte[] sign(byte[] textToSign){
        Signature signature = null;
        try {
            signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initSign(privateKeyTerminal);
            signature.update(textToSign,0,textToSign.length);
            return signature.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Sign a byte array with a specified RSA signing key
     * @param signingKey
     * @param textToSign
     * @return
     */
    private byte[] sign(RSAPrivateKey signingKey, byte[] textToSign){
        Signature signature = null;
        try {
            signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initSign(signingKey);
            signature.update(textToSign,0,textToSign.length);
            return signature.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Verifies a signature given a public key, plaintext and signature byte array
     * @param publicKey
     * @param plainText
     * @param signedBytes
     * @return
     */
    private boolean verify(RSAPublicKey publicKey, byte[] plainText, byte[] signedBytes){
        Signature signature = null;
        try {
            signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initVerify(publicKey);
            signature.update(plainText);
            return signature.verify(signedBytes, 0, signedBytes.length);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Handles a signature verification, including the splitting of the data array into a plaintext and signature part
     * @param verifyKey
     * @param plainTextLength
     * @param data
     */
    private void handleSignature(RSAPublicKey verifyKey, int plainTextLength, byte[] data){
        //First split the data into the plaintext byte array and the signature byte array
        byte[] plainText = new byte[plainTextLength];
        Util.arrayCopy(data, (short) 0, plainText, (short) 0, (short) plainTextLength);

        byte[] signature = new byte[data.length-plainTextLength];
        Util.arrayCopy(data, (short) plainTextLength, signature, (short) 0, (short) (data.length - plainTextLength));

        if (verify(verifyKey, plainText, signature)){
            System.out.println("Signature verified!");
        }else{
            System.err.println("Signature verification failed!");
            return;
        }
    }

    /**
     * Receives two bytes and an incrementation value and returns the incremented byte array
     * @param n1
     * @param n2
     * @param incrementBy
     * @return
     */
    private byte[] incrementNonceBy(byte n1, byte n2, int incrementBy){
        short old = Util.makeShort(n1, n2);
        old += incrementBy;

        byte[] nonce = {
                (byte) ((old >> 8) & 0xff),
                (byte) (old & 0xff),
        };
        return nonce;
    }

    // the key components and the signature dont fit in an apdu, the idea is send this component
    // firts and then signature of both, modulus and exponent
    public void testTerminalAuth() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, CardException {

        System.out.println("-----Test Verification Terminal-----");

        byte [] nonceBytes = new byte[2];
        secureRandom.nextBytes(nonceBytes);
        CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, nonceBytes, 2);
        ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
        System.out.println("VERIFICATION_HI: " + Integer.toHexString(responseAPDU.getSW()));

        byte [] ca = responseAPDU.getData(); // Data Ca{Ca}SKC

        if (responseAPDU.getSW() == 0x6303){
            System.out.println("Card was blocked");
            return;
        }

        if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], ca[0], ca[1], 1)){
            System.err.println("Nonce not incremented");
        }

        //Create TA
        byte[] TA = new byte[4]; //TA is our Id, incremented nonce
        byte[] nonce = incrementNonceBy(ca[0], ca[1], 1);
        Util.arrayCopy(nonce, (short) 0, TA, (short) 0, (short) 2);
        Util.arrayCopy(terminalId, (short) 0, TA, (short) 2, (short) 2);
        byte[] TASigned = sign(TA);

        byte[] CaTaTaSigned = new byte[ca.length+4+TASigned.length+2]; //We send 4 bytes of Ta, 4 bytes of CA and then the signed part of TA prepended by the message code (2 bytes)
        Util.arrayCopy(new byte[]{0x00, 0x01}, (short) 0, CaTaTaSigned, (short) 0, (short) 2); //Add the message code
        Util.arrayCopy(ca, (short) 0, CaTaTaSigned, (short) 2, (short) ca.length); //CA Part
        Util.arrayCopy(TA, (short) 0, CaTaTaSigned, (short) (2+ca.length), (short) 4); //Plaintext of TA
        Util.arrayCopy(TASigned, (short) 0, CaTaTaSigned, (short) (2+ca.length+4), (short) TASigned.length);  //Copy everything else

        //Send everything to the backend


        System.out.println("Verification hi BE" + DatatypeConverter.printHexBinary(CaTaTaSigned));

        byte[] v = new BackEndCommunicator().sendAndReceive(CaTaTaSigned); //Received from the backend composed of (plaintext Public key card, plaintext public key terminal, nonce incremented, signature digest of previous)

        //Nonce || publicKeyEncoded || exponentTerminal || modulusTerminal || signature
        System.out.println(DatatypeConverter.printHexBinary(v));

        short exponentSize = 3;
        short modulusSize = 128;
        short encodedSize = 162;

        //Check if nonce is properly incremented
        if (! isNonceIncrementedBy(nonce[0], nonce[1], v[0], v[1], 1)){
            System.err.println("Nonce is not incremented!");
            return;
        }

        //Check if signature is valid
        byte[] vPlaintext = new byte[2 + encodedSize + exponentSize + modulusSize];
        Util.arrayCopy(v, (short) 0, vPlaintext, (short) 0, (short) (v.length-128));

        short signatureSize = (short) (v.length - vPlaintext.length);
        byte[] vSignature = new byte[signatureSize]; //Buffer for signature
        Util.arrayCopy(v, (short) (vPlaintext.length), vSignature, (short) 0, signatureSize);

        System.out.println("Card ID : " + Util.makeShort(ca[2], ca[3]));

        System.out.println(DatatypeConverter.printHexBinary(vPlaintext));

        if (!verify(publicKeyBackend, vPlaintext, vSignature)) {
            System.out.println("Signature is not valid");
            return;
        }

        //Keep a copy of the public key of the card here
        byte[] publicKeyCardBytes = new byte[encodedSize];
        Util.arrayCopy(vPlaintext, (short) 2, publicKeyCardBytes, (short) 0, encodedSize);

        System.out.println("Encoded public key bytes from DB " + DatatypeConverter.printHexBinary(publicKeyCardBytes));

        byte[] publicKeyTerminalBytes = new byte[exponentSize + modulusSize];
        Util.arrayCopy(vPlaintext, (short) (2+encodedSize), publicKeyTerminalBytes, (short) 0, (short) (exponentSize+modulusSize));

        byte[] modulusBytes = new byte[modulusSize];
        byte[] exponentBytes = new byte[exponentSize];

        Util.arrayCopy(publicKeyTerminalBytes, (short) 0, exponentBytes, (short) 0, exponentSize);
        Util.arrayCopy(publicKeyTerminalBytes, exponentSize, modulusBytes, (short) 0, modulusSize);

        // Create private and public key specs
        publicKeyCard = (RSAPublicKey) keyFromEncoded(publicKeyCardBytes, 0);

        //Send to card
        CommandAPDU capdu;
        ResponseAPDU responsePrivate;

        byte[] dataToSend = new byte[2 + publicKeyTerminalBytes.length];
        byte[] nonceIncremented = incrementNonceBy(v[0], v[1], 1);
        Util.arrayCopy(nonceIncremented, (short) 0, dataToSend, (short) 0, (short) 2);
        Util.arrayCopy(publicKeyTerminalBytes, (short) 0, dataToSend, (short) 2, (short) publicKeyTerminalBytes.length);

        System.out.println(Util.makeShort(dataToSend[0], dataToSend[1]));

        // Send public key of the terminal extrated from the plaintext
        capdu = new CommandAPDU(CLASS, VERIFICATION_V, (byte) exponentBytes.length, (byte) modulusBytes.length, dataToSend);
        responsePrivate = ch.transmit(capdu);
        System.out.println("VERIFICATION_V: " + Integer.toHexString(responsePrivate.getSW()));

        // Send the signature
        capdu = new CommandAPDU(CLASS, VERIFICATION_S, (byte) 0, (byte) 0, vSignature);
        responsePrivate = ch.transmit(capdu);
        System.out.println("VERIFICATION_S: " + Integer.toHexString(responsePrivate.getSW()));
    }

    /**
     * Send the key of the backend to the card, so that it is possible for the card to verify the signatures of the backend
     * @throws CardException
     */
    public void testSendBackendKey() throws CardException {
        // Send BE key for verify signatures(this will be done in the personalization)
        byte[] exponentBytesBE = getBytes(publicKeyBackend.getPublicExponent());
        byte[] modulusBytesBE = getBytes(publicKeyBackend.getModulus());
        byte[] bytesKeyBE = new byte [modulusBytesBE.length+exponentBytesBE.length];
        Util.arrayCopy(exponentBytesBE,(short)0,bytesKeyBE,(short)0,(short)exponentBytesBE.length);
        Util.arrayCopy(modulusBytesBE,(short)0,bytesKeyBE,(short)exponentBytesBE.length,(short)modulusBytesBE.length);
        CommandAPDU capdu;
        //Changed to PERSONALIZATION_BACKEND_KEY 0x20

        System.out.println("Backend Key Bytes " + DatatypeConverter.printHexBinary(bytesKeyBE));

        capdu = new CommandAPDU(CLASS, PERSONALIZATION_BACKEND_KEY, (byte) exponentBytesBE.length, (byte) modulusBytesBE.length, bytesKeyBE, bytesKeyBE.length);
        ResponseAPDU responsePrivate = ch.transmit(capdu);
        System.out.println("BACKEND_KEY: " + Integer.toHexString(responsePrivate.getSW()));

    }

    public void testPersonalizationHi() throws CardException, NoSuchAlgorithmException {
        //generate fresh card keys
        System.out.println("Generating fresh keys");
        KeyPairGenerator generator = null;

        generator = KeyPairGenerator.getInstance("RSA");

        byte[] seed = new SecureRandom().generateSeed(20);

        generator.initialize(1024, new SecureRandom(seed));
        KeyPair pair = generator.generateKeyPair();
        tempCardPublicKey = (RSAPublicKey) pair.getPublic();
        privateKeyCard = (RSAPrivateKey) pair.getPrivate();

        // Sending modulus private key
        CommandAPDU capdu;
        byte[] modulus = getBytes(privateKeyCard.getModulus());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 0, (byte) 0, modulus);
        ResponseAPDU responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_HI private modulus: " + Integer.toHexString(responsePrivate.getSW()));

        // Sending exponent private key
        byte[] exponent = getBytes(privateKeyCard.getPrivateExponent());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 1, (byte) 0, exponent);
        responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_HI private exponent: " + Integer.toHexString(responsePrivate.getSW()));

        System.out.println("Public key" + DatatypeConverter.printHexBinary(tempCardPublicKey.getEncoded()));

        modulus = getBytes(tempCardPublicKey.getModulus());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 2, (byte) 0, modulus);
        responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_HI public modulus: " + Integer.toHexString(responsePrivate.getSW()));

        exponent = getBytes(tempCardPublicKey.getPublicExponent());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 3, (byte) 0, exponent);
        responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_HI public exponent: " + Integer.toHexString(responsePrivate.getSW()));
    }

    /**
     * Create an creation and expiration date
     * @throws CardException
     */
    private void testPesonalizationDates() throws CardException {

        // Get current date unix seconds
        int unixTime = (int)(System.currentTimeMillis() / 1000);
        byte[] personalizedDate = new byte[]{
                (byte) (unixTime >> 24),
                (byte) (unixTime >> 16),
                (byte) (unixTime >> 8),
                (byte) unixTime

        };// convert date to byte array

        //Expiration date is the current moment + two years in seconds
        int expirationTime = unixTime + 63113851;
        byte[] expirationDate = new byte[]{
                (byte) (expirationTime >> 24),
                (byte) (expirationTime >> 16),
                (byte) (expirationTime >> 8),
                (byte) expirationTime
        };

        byte[] requestId = new byte[162+6];
        byte[] publicKeyCardBytes = tempCardPublicKey.getEncoded();
        System.out.println("tempCardPublicKey Encoded length " + tempCardPublicKey.getEncoded().length);
        byte[] messageCode = new byte[]{
                0x00,
                0x02,
        };

        Util.arrayCopy(messageCode, (short) 0, requestId, (short) 0, (short) 2);
        Util.arrayCopy(publicKeyCardBytes, (short) 0, requestId, (short) 2, (short) 162);
        Util.arrayCopy(expirationDate, (short) 0, requestId, (short) (2+162), (short) 4);

        System.out.println(DatatypeConverter.printHexBinary(requestId));
        byte[] requestIdResponse = backend.sendAndReceive(requestId); //Returns the Id

        System.out.println("Card Id for the card " + DatatypeConverter.printHexBinary(requestIdResponse));

        //Receive id of the card
        byte[] id = new byte[]{
            requestIdResponse[0],
            requestIdResponse[1],
        };

        byte[] dataToSend = new byte[10];//container of data that will be sent to the card

        Util.arrayCopy(id, (short)0, dataToSend, (short)0, (short)2); //copy card id to container
        Util.arrayCopy(personalizedDate, (short)0, dataToSend, (short) 2, (short) 4);//copy date to container
        Util.arrayCopy(expirationDate, (short) 0, dataToSend, (short) 6, (short) 4); //Copy the expiration date to the container

        //send data to the card
        CommandAPDU capdu;
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_DATES, (byte) 0, (byte) 0, dataToSend);
        ResponseAPDU responsePrivate = ch.transmit(capdu);
        System.out.println("PERSONALIZATION_DATES: " + Integer.toHexString(responsePrivate.getSW()));
    }

    /**
     * Generates a random PIN
     */
    private void testPin() {
        //Generate PIN at random
        Random random = new Random();

        byte[] pin = {(byte) random.nextInt(9), (byte) random.nextInt(9), (byte) random.nextInt(9), (byte) random.nextInt(9)};
        try {
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, PERSONALIZATION_NEW_PIN, (byte) 0, (byte) 0, pin);
            ResponseAPDU responsePrivate = ch.transmit(capdu);
            System.out.println("PERSONALIZATION_NEW_PIN: " + Integer.toHexString(responsePrivate.getSW()));
            System.out.println("PIN "+ DatatypeConverter.printHexBinary(pin));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Decommisions a card
     * @throws CardException
     */
    private void testDecommissioning() throws CardException {
        System.out.println("-----Test Decommissioning-----");

        byte [] nonceBytes = new byte[2];
        secureRandom.nextBytes(nonceBytes);

        // This is the signature of the Terminal
        byte[] signedNonce = sign(nonceBytes);
        byte[] nonceSignedNonce = new byte[nonceBytes.length + signedNonce.length];

        System.arraycopy(nonceBytes,0,nonceSignedNonce,0         ,nonceBytes.length);
        System.arraycopy(signedNonce,0,nonceSignedNonce,nonceBytes.length,signedNonce.length);

        CommandAPDU hiAPDU = new CommandAPDU(CLASS, DECOMMISSIONING_HI, 0, 0, nonceSignedNonce, nonceSignedNonce.length);
        ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
        System.out.println("DECOMMISSIONING_HI: " + Integer.toHexString(responseAPDU.getSW()));
        byte [] dataRec = responseAPDU.getData();

        //Check if received nonce has been incremented
        if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], dataRec[0], dataRec[1], 1)){
            System.err.println("Nonce has not been incremeneted");
            return;
        }

        //Verify signature
        handleSignature(publicKeyCard, 4, dataRec);

        //send the received message to the backend

        // Messagecode (3) || Nonce || Card Id || Signed (Nonce || Card Id)

        byte[] dataForBackend = new byte[2+dataRec.length];
        dataForBackend[0] = 0x00;
        dataForBackend[1] = 0x03;
        Util.arrayCopy(dataRec, (short) 0, dataForBackend, (short) 2, (short) dataRec.length);

        //Receive the reponse from the backend
        byte[] backendResponse = backend.sendAndReceive(dataForBackend);

        System.out.println("Decomm response backend: " + DatatypeConverter.printHexBinary(backendResponse));

        byte[] backendNonceIncremented = new byte[2];
        Util.arrayCopy(backendResponse, (short) 0, backendNonceIncremented, (short) 0, (short) 2); //Copy the plaintext nonce of the backend

        //Check if nonce has been incremented by 2 from the backend
        if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], backendNonceIncremented[0], backendNonceIncremented[1], 2)){
            System.err.println("Nonce has not been incremented");
            return;
        }

        handleSignature(publicKeyBackend, 4, backendResponse);

        //Forward this message to the card
        hiAPDU = new CommandAPDU(CLASS, DECOMMISSIONING_CLEAR, 0, 0, backendResponse, backendResponse.length);
        responseAPDU = ch.transmit(hiAPDU);
        System.out.println("DECOMMISSIONING_CLEAR: " + Integer.toHexString(responseAPDU.getSW()));
    }

    /**
     * Test the reloading
     * @param amount
     * @throws CardException
     */
    public void testReloading(short amount) throws CardException {
        System.out.println("-----Test Reloading-----");

        byte [] nonceBytes = new byte[2];
        secureRandom.nextBytes(nonceBytes);
        short firstShort = Util.makeShort(nonceBytes[0], nonceBytes[1]);

        //Sign the nonce
        byte[] signedNonce = sign(nonceBytes);
        byte[] combinedData = new byte[nonceBytes.length + signedNonce.length];

        System.arraycopy(nonceBytes,0,combinedData,0         ,nonceBytes.length);
        System.arraycopy(signedNonce,0,combinedData,nonceBytes.length,signedNonce.length);

        System.out.println(firstShort);
        System.out.println("Send in reloading Hi: " + DatatypeConverter.printHexBinary(combinedData));
        CommandAPDU hiAPDU = new CommandAPDU(CLASS, RELOADING_HI, 0, 0, combinedData, combinedData.length);
        ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
        System.out.println("RELOADING_HI: " + Integer.toHexString(responseAPDU.getSW()));

        byte [] incrementedNonce = responseAPDU.getData();

        System.out.println("Response reloading Hi: " + DatatypeConverter.printHexBinary(incrementedNonce));
        //Check if nonce is incremented

        if (!isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], incrementedNonce[0], incrementedNonce[1], 1)) {
            System.err.println("Nonce has not been incremented");
            return;
        }

        System.out.println("Exponent : " + DatatypeConverter.printHexBinary(publicKeyCard.getPublicExponent().toByteArray()));
        System.out.println("Moduslus : " + DatatypeConverter.printHexBinary(publicKeyCard.getModulus().toByteArray()));

        handleSignature(publicKeyCard, 4, incrementedNonce);

        //Forward this message to the backend

        //MessageCode || Tid || Amount || Signed(Tid || Amount) || Nonce || Card Id || Signature (Nonce || CardId)

        //Sign the amount

        byte[] requestForReload = getReloadRequest(amount, incrementedNonce);

        //Receive bytes from the backend
        byte[] backendResponse = backend.sendAndReceive(requestForReload);  //Returns Nonce || newbalance || signed

        System.out.println("Response " + DatatypeConverter.printHexBinary(backendResponse));

        if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], backendResponse[0], backendResponse[1], 2)){
            System.err.println("Nonce has not been incremented");
            return;
        }

        //Signature verification
        handleSignature(publicKeyBackend, 4, backendResponse);

        //Send to card (Nonce, Id, Amount) || signed
        byte[] incrementNonce = incrementNonceBy(backendResponse[0], backendResponse[1], 1);
        short balance = Util.makeShort(backendResponse[2], backendResponse[3]);
        short newBalance = (short) (balance + amount);

        byte [] dataToSend = new byte[]{
                incrementNonce[0],  //Nonce received from backend incremented
                incrementNonce[1],  //""
                incrementedNonce[2],    //Card Id
                incrementedNonce[3],    //Card ID
                (byte) (newBalance >> 8),   //New balance
                (byte) newBalance       //New balance
        };

        byte[] signedBytes = sign(dataToSend);
        byte [] bytesApdu = new byte[128+6];
        System.arraycopy(dataToSend,0, bytesApdu,0,6);
        System.arraycopy(signedBytes,0, bytesApdu,6,128);

        System.out.println(DatatypeConverter.printHexBinary(bytesApdu));
        hiAPDU = new CommandAPDU(CLASS, RELOADING_UPDATE, 0, 0, bytesApdu, bytesApdu.length);
        responseAPDU = ch.transmit(hiAPDU);
        System.out.println("RELOADING_UPDATE: " + Integer.toHexString(responseAPDU.getSW()));
        System.out.println("Response: " + DatatypeConverter.printHexBinary(responseAPDU.getData()));
    }

    /**
     * Create a request for the backend indicating to return the balance of a given card
     * @param amount
     * @param signedCard
     * @return
     */
    private byte[] getReloadRequest(short amount, byte[] signedCard){
        byte[] requestForReload = new  byte[6+128+signedCard.length];

        requestForReload[0] = 0x00;
        requestForReload[1] = 0x04;
        requestForReload[2] = terminalId[0];
        requestForReload[3] = terminalId[1];
        requestForReload[4] = (byte) (amount >> 8);
        requestForReload[5] = (byte) amount;
        byte[] amountSigned = sign(new byte[]{terminalId[0], terminalId[1], requestForReload[4], requestForReload[5]}); //Sign the terminal Id || Amount

        Util.arrayCopy(amountSigned, (short) 0, requestForReload, (short) 6, (short) amountSigned.length);
        Util.arrayCopy(signedCard, (short) 0, requestForReload, (short) (6+amountSigned.length), (short) signedCard.length);
        return requestForReload;
    }

    /**
     * Encrypt the input byte array with the given RSA public key
     * @param input
     * @param publickey
     * @return
     */
    private byte[] encrypt(byte[] input, RSAPublicKey publickey){
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publickey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Test the crediting of a card
     * @throws CardException
     */
    private void testCrediting() throws CardException {

        System.out.println("-----Test Crediting-----");

        byte [] nonceBytes = new byte[2];
        secureRandom.nextBytes(nonceBytes);
        short firstShort = Util.makeShort(nonceBytes[0], nonceBytes[1]);

        // This is the signature of the Terminal
        byte[] signedNonce = sign(nonceBytes);
        byte[] combinedData = new byte[nonceBytes.length + signedNonce.length];

        System.arraycopy(nonceBytes,0,combinedData,0         ,nonceBytes.length);
        System.arraycopy(signedNonce,0,combinedData,nonceBytes.length,signedNonce.length);

        System.out.println("T->C: Credit Hi " + DatatypeConverter.printHexBinary(combinedData));

        CommandAPDU hiAPDU = new CommandAPDU(CLASS, CREDIT_HI, 0, 0, combinedData, combinedData.length);
        ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
        System.out.println("CREDIT_HI: " + Integer.toHexString(responseAPDU.getSW()));
        byte [] incrementedNonce = responseAPDU.getData();

        System.out.println("C->T: Credit Hi " + DatatypeConverter.printHexBinary(incrementedNonce));

        //Verify nonce incremented
        if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], incrementedNonce[0], incrementedNonce[1], 1)){
            System.err.println("Nonce has not been incremented");
            return;
        }

        //Verify the signature on the card Id and the nonce
        handleSignature(publicKeyCard, 4, incrementedNonce);
        System.out.println("hallo");

        //Forward the request to the backend

        // Request the correct balance (ie. reloading with amount 0)
        byte[] requestForReload = getReloadRequest((short) 0, incrementedNonce);

        //Receive bytes from the backend
        byte[] backendResponse = backend.sendAndReceive(requestForReload);  //Returns Nonce || newbalance || signed

        //Receive the correct balance from the backend
        short receivedBalance = Util.makeShort(backendResponse[2], backendResponse[3]);
        //Todo make credit amount non-fixed
        short creditAmount = 88;

        if(receivedBalance-creditAmount< 0){
            System.out.println("Error negative balance");
            return;
        }

        nonceBytes = incrementNonceBy(backendResponse[0], backendResponse[1], 1);

        short newBalance = (short) (receivedBalance - creditAmount);

        byte[] dataToSend = null;
        byte instruction;

        if(creditAmount>20){
            Scanner scanner = new Scanner(System.in);
            byte[] pinArray = new byte[4];
            System.out.println("Enter your PIN:");
            String pin = scanner.next();

            for (int i = 0 ; i < pin.length(); i++){
                pinArray[i] = (byte)  (pin.charAt(i) - 48);
            }

            byte[] pinEncrypted = encrypt(pinArray, publicKeyCard);

            //Save everything to the dataToSend array
            dataToSend = new byte[pinEncrypted.length + 4];
            dataToSend[0] = nonceBytes[0];
            dataToSend[1] = nonceBytes[1];
            dataToSend[2] = (byte) (creditAmount >> 8);
            dataToSend[3] = (byte) (creditAmount);
            Util.arrayCopy(pinEncrypted, (short) 0, dataToSend, (short) 4, (short) pinEncrypted.length);

            instruction = CREDIT_COMMIT_PIN;
        }else{
            instruction = CREDIT_COMMIT_NO_PIN;

            byte[] data = new byte[]{
                nonceBytes[0],
                nonceBytes[1],
                (byte) (creditAmount >> 8),
                (byte) creditAmount
            };

            byte[] dataToSendSigned = sign(data);
            dataToSend = new byte[4 + dataToSendSigned.length];
            Util.arrayCopy(data, (short) 0, dataToSend, (short) 0, (short) 4);
            Util.arrayCopy(dataToSendSigned, (short) 0, dataToSend, (short) 4, (short) 128);
        }


        System.out.println(DatatypeConverter.printHexBinary(dataToSend));

        if (creditAmount > 20){
            //Send in two APDUs, first one has the plaintext of the nonce, amount and encrypted(pin)
            hiAPDU = new CommandAPDU(CLASS, instruction, 0, 0, dataToSend, dataToSend.length);
            responseAPDU = ch.transmit(hiAPDU);

            //Second APDU has the signed (nonce, amount).
            byte[] dataToSendNoPIN = new byte[4];
            Util.arrayCopy(dataToSend, (short) 0, dataToSendNoPIN, (short) 0, (short) 4);
            byte[] dataTosendNoPINSigned = sign(dataToSendNoPIN);

            hiAPDU = new CommandAPDU(CLASS, instruction, 1, 0, dataTosendNoPINSigned, (short) dataTosendNoPINSigned.length);
            responseAPDU = ch.transmit(hiAPDU);

            //Todo: Check if the pin is good
            if (responseAPDU.getSW() == 27013){
                //Pin is wrong
                System.err.println("Wrong pin!");
                return;
            }else if (responseAPDU.getSW() == 0x6305){
                //No more pin attempts
                System.err.println("No more pin attempts");
                return;
            }else if (responseAPDU.getSW() == 0x6301){
                System.err.println("PIN is required");
                return;
            }
        }else{
            System.out.println("No pin data to card " + DatatypeConverter.printHexBinary(dataToSend));
            hiAPDU = new CommandAPDU(CLASS, instruction, 0, 0, dataToSend, dataToSend.length);
            responseAPDU = ch.transmit(hiAPDU);
        }

        System.out.println("CREDITING_UPDATE: " + Integer.toHexString(responseAPDU.getSW()));
        System.out.println("Response: " + DatatypeConverter.printHexBinary(responseAPDU.getData()));

        //Receive the commitment from the card

        byte[] cardPayCommitment = responseAPDU.getData();



        //Verify the incrementation
        if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], cardPayCommitment[0], cardPayCommitment[1], 1)){
            System.err.println("Nonce has not been incremented");
            return;
        }


        //Check signature on ( Nonce || Id || Amount )
        handleSignature(publicKeyCard, 6, cardPayCommitment);

        System.out.println("Continued");

        //Forward the request to the backend

        // Messagecode (0x00, 0x05) || Nonce || CardId || Amount || Signature (nonce || cardId || amount)

        //Receive the final message
        byte[] dataForBackend = new byte[2+cardPayCommitment.length];
        dataForBackend[0] = 0x00;
        dataForBackend[1] = 0x05;
        Util.arrayCopy(cardPayCommitment, (short) 0, dataForBackend, (short) 2, (short) cardPayCommitment.length);

        backendResponse = backend.sendAndReceive(dataForBackend); //Only the nonce signed, implicit indication that the protcol has finished

        System.out.println(DatatypeConverter.printHexBinary(backendResponse));

        //Verify nonce incremented
        if (! isNonceIncrementedBy(cardPayCommitment[0], cardPayCommitment[1], backendResponse[0], backendResponse[1], 1)){
            System.err.println("Nonce has not been incremented");
            return;
        }

        //Verify the signature
        handleSignature(publicKeyBackend, 2, backendResponse);

        System.out.println("Crediting completed");
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

    public static void main(String[] args) {
        Terminal terminal = new Terminal(new BackEndCommunicator());
        //new Thread(Terminal).run();
    }




}

