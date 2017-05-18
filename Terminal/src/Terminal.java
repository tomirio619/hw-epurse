import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

/**
 * Created by Tomirio on 9-5-2017.
 */
public class Terminal {

    private KeyPair pair;
    private ECPublicKey terminalPublicKey;
    private ECPrivateKey terminalPrivateKey;

    private ECPublicKey cardPublicKey;

    public static void main(String[] args) {
        TerminalThread terminalThread = new TerminalThread();
        new Thread(terminalThread).run();
    }
}
