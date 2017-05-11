import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;
import java.security.SecureRandom;
import java.sql.DataTruncation;
import java.util.List;

/**
 * Created by Tomirio on 9-5-2017.
 */
public class TerminalThread implements Runnable {

    private static final String APPLET_AID = "a0404142434445461001";
    private static final byte CLASS = (byte) 0xB0;
    private final static byte VERIFICATION_HI = (byte) 0x41;

    @Override
    public void run() {
        try {
            TerminalFactory tf = TerminalFactory.getDefault();
            CardTerminals ct = tf.terminals();
            List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);
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

                            //1. Terminal sends Hi
                            byte[] payload = new byte[2];
                            new SecureRandom().nextBytes(payload);
                            short random = Util.makeShort(payload[0], payload[1]);
                            random = (short) Math.abs(random);
                            System.out.println(random);

                            CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, payload, 2);
                            ResponseAPDU responseHi = ch.transmit(hiAPDU);
                            byte[] randomInc = responseHi.getData();
                            short incremented = Util.makeShort(randomInc[0], randomInc[1]);
                            System.out.println(incremented);

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
}
