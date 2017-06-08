import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.licel.jcardsim.smartcardio.JCardSimProvider;
import ePurse.Epurse;
import javacard.framework.AID;
import javacard.framework.CardException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.*;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import sun.security.rsa.RSAPrivateKeyImpl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

/**
 * Created by Tomirio on 10-5-2017.
 * See https://github.com/licel/jcardsim/tree/jc2.2.1
 */
public class Simulator extends TestCase {



    private static final String APPLET_AID = "a0404142434445461001";
    private static final byte CLASS = (byte) 0xB0;
    private final static byte EPURSE_CLA = (byte) 0xba;
    private final static byte PERSONALIZATION_BACKEND_KEY = (byte) 0x20;
    private final static byte PERSONALIZATION_HI = (byte) 0x30;
    private final static byte PERSONALIZATION_DATES = (byte) 0x31;
    private final static byte PERSONALIZATION_NEW_PIN = (byte) 0x32;

    private final static byte DECOMMISSIONING_HI = (byte) 0x33;
    private final static byte DECOMMISSIONING_CLEAR = (byte) 0x34;

    private final static byte RELOADING_HI = (byte) 0x35;
    private final static byte RELOADING_UPDATE = (byte) 0x36;

    private final static byte CREDIT_HI = (byte) 0x37;
    private final static byte CREDIT_COMMIT_PIN = (byte) 0x38;
    private final static byte CREDIT_COMMIT_NO_PIN = (byte) 0x39;
    private final static byte CREDIT_NEW_BALANCE = (byte) 0x40;

    private final static byte VERIFICATION_HI = (byte) 0x41;
    private final static byte VERIFICATION_V = (byte) 0x42;
    private final static byte VERIFICATION_S = (byte) 0x47;

    private final static byte SEND_DECRYPTIONKEY = (byte) 0x44;

    private final static byte SEND_KEYPAIR = (byte) 0x43;
    private final static byte SEND_KEYPAIR_RSA = (byte) 0x45;
    private final static byte BACKEND_KEY = (byte) 0x46;


    private static boolean setUpIsDone = false;
    private static CardChannel cardChannel = null;
    private static JavaxSmartCardInterface simulator = null;
    SecureRandom secureRandom;
    private byte[] terminalId = new byte[]{0x00, 0x01};


    private RSAPublicKey publicKeyBackend;
    private RSAPrivateKey privateKeyBackend;

    private RSAPublicKey publicKeyTerminal;
    private RSAPrivateKey privateKeyTerminal;

    private RSAPublicKey publicKeyCard;
    private BackEndCommunicator backend;




    public void testSelect() throws CardException, NoSuchAlgorithmException, javax.smartcardio.CardException {
        System.out.println("Test Select");
        // select applet
        CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(APPLET_AID));
        ResponseAPDU response = cardChannel.transmit(selectApplet);
        assertEquals(0x9000, response.getSW());
    }

    void loadBackendKeys() throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
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
        /*Signature signature = Signature.getInstance("SHA1withRSA", "BC");
        signature.initSign(privateKeyBackend);
        signature.update((byte)20);
        byte [] bytesSignature = signature.sign();
        int lengthSignature = bytesSignature.length;

        signature.initVerify(publicKeyBackend);
        signature.update((byte)20);
        //Lets check it
        boolean verified = signature.verify(bytesSignature, 0, lengthSignature);
        System.out.println(verified);
*/
}

    private void loadTerminalKeys() {
        //First generate test terminal keypair
        KeyPairGenerator g = null;
        try {
            g = KeyPairGenerator.getInstance("RSA", "BC");
            g.initialize(1024, new SecureRandom());
            java.security.KeyPair pairT = g.generateKeyPair();
            publicKeyTerminal = (RSAPublicKey) pairT.getPublic();
//            System.out.println(publicKeyCard.getEncoded());
            //System.out.println("Terminal public: " + DatatypeConverter.printHexBinary(publicKeyTerminal.getEncoded()));
            privateKeyTerminal = (RSAPrivateKey) pairT.getPrivate();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    @BeforeClass
    protected void setUp() throws Exception {
        if (setUpIsDone) {
            return;
        }

        System.out.println("Set Up");
        secureRandom = new SecureRandom();

        if (Security.getProvider("jCardSim") == null) {
            JCardSimProvider provider = new JCardSimProvider();
            Security.addProvider(provider);
        }
        TerminalFactory tf = TerminalFactory.getInstance("jCardSim", null);
        CardTerminals ct = tf.terminals();
        List<CardTerminal> list = ct.list();
        CardTerminal jcsTerminal = null;
        for (CardTerminal aList : list) {
            if (aList.getName().equals("jCardSim.Terminal")) {
                jcsTerminal = aList;
                break;
            }
        }
        // check terminal exists
        assertTrue(jcsTerminal != null);
        // check if card is present
        assertTrue(jcsTerminal.isCardPresent());
        // check card
        Card jcsCard = jcsTerminal.connect("T=0");
        assertTrue(jcsCard != null);
        // check card ATR
        cardChannel = jcsCard.getBasicChannel();
        assertTrue(cardChannel != null);
        // Install the applet
        simulator = new JavaxSmartCardInterface();
        byte[] appletAID = Hex.decode(APPLET_AID);
        AID aid = new AID(appletAID, (short) 0, (byte) appletAID.length);
        simulator.installApplet(aid, Epurse.class);
        simulator.selectApplet(aid);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        setUpIsDone = true;

        loadBackendKeys();
        loadTerminalKeys();

        backend = new BackEndCommunicator();
    }

    // Send all step personalization
    private void personalizationFull() throws javax.smartcardio.CardException, NoSuchAlgorithmException, CardException {

        System.out.println("-----Test Personalization-----");
        testSendBackendKey();
        testPersonalizationHi();
        testPesonalizationDates();
        testPin();
    }

    public void testSendBackendKey() throws javax.smartcardio.CardException {
        // Send BE key for verify signatures(this will be done in the personalization)
        byte[] exponentBytesBE = getBytes(publicKeyBackend.getPublicExponent());
        byte[] modulusBytesBE = getBytes(publicKeyBackend.getModulus());
        byte[] bytesKeyBE = new byte [modulusBytesBE.length+exponentBytesBE.length];
        Util.arrayCopy(exponentBytesBE,(short)0,bytesKeyBE,(short)0,(short)exponentBytesBE.length);
        Util.arrayCopy(modulusBytesBE,(short)0,bytesKeyBE,(short)exponentBytesBE.length,(short)modulusBytesBE.length);
        CommandAPDU capdu;
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_BACKEND_KEY, (byte) exponentBytesBE.length, (byte) modulusBytesBE.length, bytesKeyBE);
        ResponseAPDU responsePrivate = simulator.transmitCommand(capdu);
        System.out.println("BACKEND_KEY: " + Integer.toHexString(responsePrivate.getSW()));

    }

    public void testSignatureRSA() {

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
            ResponseAPDU responsePrivate = simulator.transmitCommand(capdu);
            System.out.println("SEND_KEYPAIR modulus: " + responsePrivate.getSW());


            byte[] exponent = getBytes(privatekey.getPrivateExponent());
            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 1, (byte) 0, exponent);
            responsePrivate = simulator.transmitCommand(capdu);
            System.out.println("SEND_KEYPAIR exponent: " + responsePrivate.getSW());

            capdu = new CommandAPDU(CLASS, SEND_KEYPAIR, (byte) 0, (byte) 0, 0);
            responsePrivate = simulator.transmitCommand(capdu);
            System.out.println("SIGNING Request: " + responsePrivate.getSW());

            Signature signature = Signature.getInstance("RSA", "BC");
            signature.initVerify(publickey);
            signature.update((byte) 42);
            //Lets check it
            assertTrue(signature.verify(responsePrivate.getData(), 1, responsePrivate.getData().length));

        } catch (Exception e) {

        }

    }

    // the key components and the signature dont fit in an apdu, the idea is send this component
    // firts and then signature of both, modulus and exponent
    public void testTerminalAuth() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, javax.smartcardio.CardException, CardException, SignatureException {

        personalizationFull();


        System.out.println("-----Test Verification Terminal-----");

        byte [] nonceBytes = new byte[2];
        secureRandom.nextBytes(nonceBytes);
        CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, nonceBytes, 2);
        ResponseAPDU responseAPDU = cardChannel.transmit(hiAPDU);
        System.out.println("VERIFICATION_HI: " + Integer.toHexString(responseAPDU.getSW()));

        byte [] ca = responseAPDU.getData(); // Data Ca{Ca}SKC

        if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], ca[0], ca[1], 1)){
            System.out.println("Nonce not incremented");
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

        byte[] v = backend.sendAndReceive(CaTaTaSigned); //Received from the backend composed of (plaintext Public key card, plaintext public key terminal, nonce incremented, signature digest of previous)


        //Nonce || exponentCard || modulusCard || exponentTerminal || modulusTerminal || signature
        System.out.println(DatatypeConverter.printHexBinary(v));

        short exponentSize = 3;
        short modulusSize = 129;

        //Check if nonce is properly incremented
        if (! isNonceIncrementedBy(nonce[0], nonce[1], v[0], v[1], 1)){
            System.out.println("Nonce is not incremented!");
            return;
        }

        //Check if signature is valid
        byte[] vPlaintext = new byte[2*exponentSize+2*modulusSize+2];
        Util.arrayCopy(v, (short) 0, vPlaintext, (short) 0, (short) (v.length-128));

        short signatureSize = (short) (v.length - vPlaintext.length);
        byte[] vSignature = new byte[signatureSize]; //Buffer for signature
        Util.arrayCopy(v, (short) (vPlaintext.length), vSignature, (short) 0, signatureSize);

        System.out.println(DatatypeConverter.printHexBinary(vPlaintext));

        if (!verify(publicKeyBackend, vPlaintext, vSignature)) {
            System.out.println("Signature is not valid");
            return;
        }

        //Keep a copy of the public key of the card here
        byte[] publicKeyCardBytes = new byte[exponentSize + modulusSize];
        Util.arrayCopy(vPlaintext, (short) 2, publicKeyCardBytes, (short) 0, (short) (exponentSize+modulusSize));

        byte[] publicKeyTerminalBytes = new byte[exponentSize + modulusSize];
        Util.arrayCopy(vPlaintext, (short) (2+exponentSize+modulusSize), publicKeyTerminalBytes, (short) 0, (short) (exponentSize+modulusSize));

        byte[] modulusBytes = new byte[modulusSize];
        byte[] exponentBytes = new byte[exponentSize];

        //Todo: look at whether this is correct. Only works if the RSA public key that has been received was send using the getEncoded() function
        Util.arrayCopy(publicKeyCardBytes, (short) 0, modulusBytes, (short) 0, modulusSize);
        Util.arrayCopy(publicKeyCardBytes, modulusSize, exponentBytes, (short) 0, exponentSize);

        BigInteger modulus = new BigInteger(modulusBytes);
        BigInteger exponent = new BigInteger(exponentBytes);

        // Create private and public key specs
        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, exponent);

        // Create a key factory
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
            // Create the RSA private and public keys
            publicKeyCard = (RSAPublicKey) factory.generatePublic(publicSpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        //Send to card
        CommandAPDU capdu;
        ResponseAPDU responsePrivate;

        byte[] dataToSend = new byte[2 + publicKeyTerminalBytes.length];
        dataToSend[0] = v[0];
        dataToSend[1] = v[1];
        Util.arrayCopy(publicKeyTerminalBytes, (short) 0, dataToSend, (short) 2, (short) publicKeyTerminalBytes.length);

        System.out.println(Util.makeShort(dataToSend[0], dataToSend[1]));

        // Send public key of the terminal extrated from the plaintext
        capdu = new CommandAPDU(CLASS, VERIFICATION_V, (byte) exponentBytes.length, (byte) modulusBytes.length, dataToSend);
        responsePrivate = cardChannel.transmit(capdu);
        System.out.println("VERIFICATION_V: " + Integer.toHexString(responsePrivate.getSW()));

        // Send the signature
        capdu = new CommandAPDU(CLASS, VERIFICATION_S, (byte) 0, (byte) 0, vSignature);
        responsePrivate = cardChannel.transmit(capdu);
        System.out.println("VERIFICATION_S: " + Integer.toHexString(responsePrivate.getSW()));
    }


    public void testEncryption() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //First generate a encryption keypair
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "BC");
        g.initialize(1024, new SecureRandom());
        java.security.KeyPair pair = g.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();


        byte[] plainText = new byte[]{0x42};
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        byte[] cipherText = cipher.doFinal(plainText);

        byte[] exponentBytes = privateKey.getPrivateExponent().toByteArray();
        byte[] modulusBytes = privateKey.getModulus().toByteArray();
        //Append the two byte arrays into one
        ByteBuffer bb = ByteBuffer.allocate(exponentBytes.length);
        bb.put(exponentBytes);
//        bb.put(modulusBytes);
//        bb.put(cipherText);
        byte[] decryptionKeyBytes = bb.array();
        System.out.println("Sending exponent, modulus and ciphertext. Size: " + decryptionKeyBytes.length);

        CommandAPDU sendDecryptionKeyAPDU = new CommandAPDU(CLASS, SEND_DECRYPTIONKEY, 0, 0, exponentBytes, 127);
        ResponseAPDU responseDecryption = simulator.transmitCommand(sendDecryptionKeyAPDU);
        System.out.println(DatatypeConverter.printHexBinary(responseDecryption.getData()));
    }

    public void testVerify() throws javax.smartcardio.CardException, InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        System.out.println("Test Verify");
        //1. Terminal sends Hi
        byte[] payload = new byte[2];
        secureRandom.nextBytes(payload);
        short random = Util.makeShort(payload[0], payload[1]);
        System.out.println(random);
        CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, payload, 2);
        ResponseAPDU responseHi = simulator.transmitCommand(hiAPDU);
        byte[] randomInc = responseHi.getData();


//        short incremented = Util.makeShort(randomInc[0], randomInc[1]);
//
//        assertEquals(random+1, incremented);
    }

    public void testPersonalizationHi() throws NoSuchAlgorithmException {
        KeyPairGenerator generator  = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        java.security.KeyPair keypair = generator.generateKeyPair();
        RSAPublicKey cardPublickey = (RSAPublicKey) keypair.getPublic();
        publicKeyCard = cardPublickey;
        RSAPrivateKey cardPrivateKey = (RSAPrivateKey) keypair.getPrivate();

        //byte [] nonceBytes = new byte[2];
        //secureRandom.nextBytes(nonceBytes);

        byte[] modulus = getBytes(cardPrivateKey.getModulus());
        // Sending modulus private key
        CommandAPDU capdu;
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 0, (byte) 0, modulus);
        ResponseAPDU responsePrivate = simulator.transmitCommand(capdu);
        System.out.println("PERSONALIZATION_HI private modulus: " + Integer.toHexString(responsePrivate.getSW()));

        // Sending exponent private key
        byte[] exponent = getBytes(cardPrivateKey.getPrivateExponent());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 1, (byte) 0, exponent);
        responsePrivate = simulator.transmitCommand(capdu);
        System.out.println("PERSONALIZATION_HI private exponent: " + Integer.toHexString(responsePrivate.getSW()));

        modulus = getBytes(cardPublickey.getModulus());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 2, (byte) 0, modulus);
        responsePrivate = simulator.transmitCommand(capdu);
        System.out.println("PERSONALIZATION_HI public modulus: " + Integer.toHexString(responsePrivate.getSW()));

        exponent = getBytes(cardPublickey.getPublicExponent());
        capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 3, (byte) 0, exponent);
        responsePrivate = simulator.transmitCommand(capdu);
        System.out.println("PERSONALIZATION_HI public exponent: " + Integer.toHexString(responsePrivate.getSW()));

    }

    public void testPesonalizationDates() throws CardException {

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
        ResponseAPDU responsePrivate = simulator.transmitCommand(capdu);
        System.out.println("PERSONALIZATION_DATES: " + Integer.toHexString(responsePrivate.getSW()));

    }


    /**
     * Initialization involves transferring the private key to the smartcard.
     * In addition, the public key of the backend is transferred to the card.
     * Once this is done, the state of the card should have changed from "RAW" to "INITIALIZED".
     * @throws NoSuchAlgorithmException
     */
    public void testInitialization() throws NoSuchAlgorithmException {
        System.out.println("Test Initialization");

        KeyPairGenerator generator  = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair keypair = generator.generateKeyPair();
        RSAPublicKey cardPublickey = (RSAPublicKey) keypair.getPublic();
        RSAPrivateKey cardPrivateKey = (RSAPrivateKey) keypair.getPrivate();
        RSAPublicKey backendPublicKey = null; // TODO retrieve the backend public key

        // Transferring the private key to the card

        byte[] modulus = getBytes(cardPrivateKey.getModulus());

        // Sending modulus
        CommandAPDU capdu;
        capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 0, (byte) 0, modulus);
        ResponseAPDU responsePrivate = simulator.transmitCommand(capdu);
        System.out.println("SEND_KEYPAIR modulus: "+ responsePrivate.getSW());

        // Sending exponent
        byte[] exponent = getBytes(cardPrivateKey.getPrivateExponent());
        capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 1, (byte) 0, exponent);
        responsePrivate = simulator.transmitCommand(capdu);
        System.out.println("SEND_KEYPAIR exponent: "+ responsePrivate.getSW());

    }

    public void testPin() {

        byte[] pin = {1, 2, 3, 4};
        try {
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, PERSONALIZATION_NEW_PIN, (byte) 0, (byte) 0, pin);
            ResponseAPDU responsePrivate = simulator.transmitCommand(capdu);
            System.out.println("Set pin: " + Integer.toHexString(responsePrivate.getSW()));

            //capdu = new CommandAPDU(CLASS, CREDIT_COMMIT_PIN, (byte) 0, (byte) 0, pin);
            //responsePrivate = simulator.transmitCommand(capdu);
            //System.out.println("Check pin: " + Integer.toHexString(responsePrivate.getSW()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    byte[] getBytes(BigInteger big) {
        byte[] data = big.toByteArray();
        if (data[0] == 0) {
            byte[] tmp = data;
            data = new byte[tmp.length - 1];
            System.arraycopy(tmp, 1, data, 0, tmp.length - 1);
        }
        return data;
    }

    private byte[] incrementNonceBy(byte n1, byte n2, int incrementBy){
        short old = Util.makeShort(n1, n2);
        old += incrementBy;

        byte[] nonce = {
                (byte) ((old >> 8) & 0xff),
                (byte) (old & 0xff),
        };
        return nonce;
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

    private boolean verify(PublicKey publicKey, byte[] plainText, byte[] signedBytes){
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


}
