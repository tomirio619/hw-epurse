import javax.smartcardio.*;
import java.util.List;

/**
 * Created by Tomirio on 9-5-2017.
 */
public class TerminalThread implements Runnable {
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
