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
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * Created by Tomirio on 10-5-2017.
 * See https://github.com/licel/jcardsim/tree/jc2.2.1
 */
public class Simulator extends TestCase {

    private static final String APPLET_AID = "a0404142434445461001";
    private static final byte CLASS = (byte) 0xB0;
    private final static byte EPURSE_CLA = (byte) 0xba;
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
    private final static byte SEND_DECRYPTIONKEY = (byte) 0x44;

    private final static byte SEND_KEYPAIR = (byte) 0x43;
    private final static byte SEND_KEYPAIR_RSA = (byte) 0x45;

    private static boolean setUpIsDone = false;
    private static CardChannel cardChannel = null;
    private static JavaxSmartCardInterface simulator = null;
    SecureRandom secureRandom;



    public void testSelect() throws CardException, NoSuchAlgorithmException, javax.smartcardio.CardException {
        System.out.println("Test Select");
        // select applet
        CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(APPLET_AID));
        ResponseAPDU response = cardChannel.transmit(selectApplet);
        assertEquals(0x9000, response.getSW());
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

    public void testPersonalization(){
        System.out.println("Test Personalization");

        byte [] nonceBytes = new byte[2];
        secureRandom.nextBytes(nonceBytes);
        CommandAPDU hiAPDU = new CommandAPDU(CLASS, PERSONALIZATION_HI, 0, 0, nonceBytes, 2);
        ResponseAPDU responseAPDU = simulator.transmitCommand(hiAPDU);
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
            System.out.println("Set pin: " + responsePrivate.getSW());

            capdu = new CommandAPDU(CLASS, CREDIT_COMMIT_PIN, (byte) 0, (byte) 0, pin);
            responsePrivate = simulator.transmitCommand(capdu);
            System.out.println("Check pin: " + responsePrivate.getSW());

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


}
