import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.licel.jcardsim.smartcardio.JCardSimProvider;
import ePurse.Epurse;
import javacard.framework.AID;
import javacard.framework.CardException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.*;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.Signature;
import java.security.interfaces.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
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
    private final static byte SEND_KEYPAIR = (byte) 0x43;
    private final static byte SEND_DECRYPTIONKEY = (byte) 0x44;

    private static boolean setUpIsDone = false;
    private static CardChannel cardChannel = null;
    private static JavaxSmartCardInterface simulator = null;
    private static RandomData randomData = null;

    public void testSelect() throws CardException, NoSuchAlgorithmException, javax.smartcardio.CardException {
        System.out.println("Test Select");
        // select applet
        CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(APPLET_AID));
        ResponseAPDU response = cardChannel.transmit(selectApplet);
        assertEquals(0x9000, response.getSW());
    }

    @BeforeClass
    protected void setUp() throws Exception {
        if (setUpIsDone){
            return;
        }

        System.out.println("Set Up");

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
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        setUpIsDone = true;
    }

    public void testSignature() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        //First generate a signing keypair

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
        new SecureRandom().nextBytes(payload);
        short random = Util.makeShort(payload[0], payload[1]);
        random = (short) Math.abs(random);
        System.out.println(random);

        CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, payload, 2);
        ResponseAPDU responseHi = simulator.transmitCommand(hiAPDU);
        byte[] randomInc = responseHi.getData();



//        short incremented = Util.makeShort(randomInc[0], randomInc[1]);
//
//        assertEquals(random+1, incremented);
    }

}
