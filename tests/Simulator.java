import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.licel.jcardsim.smartcardio.JCardSimProvider;
import ePurse.Epurse;
import javacard.framework.AID;
import javacard.framework.CardException;
import javacard.framework.ISO7816;
import jdk.nashorn.internal.ir.Terminal;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.List;

/**
 * Created by Tomirio on 10-5-2017.
 * See https://github.com/licel/jcardsim/tree/jc2.2.1
 */
public class Simulator extends TestCase {

    private static final String APPLET_AID = "a040414243444546";
    private static final String CUSTOM_AID = "b040414243444547";

    public void testProvider() throws CardException, NoSuchAlgorithmException, javax.smartcardio.CardException {
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
        CardChannel jcsChannel = jcsCard.getBasicChannel();
        assertTrue(jcsChannel != null);
        // Install the applet
        JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();
        byte[] appletAID = Hex.decode(APPLET_AID);
        AID aid = new AID(appletAID, (short) 0, (byte) appletAID.length);
        simulator.installApplet(aid, Epurse.class);
        simulator.selectApplet(aid);
        // select applet
        CommandAPDU selectApplet = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(APPLET_AID));
        ResponseAPDU response = jcsChannel.transmit(selectApplet);
        assertEquals(0x9000, response.getSW());
    }

}
