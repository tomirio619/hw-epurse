import javax.smartcardio.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.security.SecureRandom;

/**
 * Created by jagipas on 17/05/2017.
 */
public class PersonalizationTerminal extends JPanel implements ActionListener {


    static final int BLOCKSIZE = 128;

    static final String TITLE = "Initiate E-Purse";
    static final int DISPLAY_WIDTH = 30;
    static final int DISPLAY_HEIGHT = 15;
    static final int AMOUNT_WIDTH = 30;
    static final int AMOUNT_HEIGHT = 1;
    static final Font FONT = new Font("Monospaced", Font.BOLD, 24);


    static final String MSG_ERROR = "Error";
    static final String MSG_INVALID = "Invalid";

    static final byte[] APPLET_AID = { (byte) 0x3B, (byte) 0x29,
            (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };


    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00,
            (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID);

    private static final byte CLA_WALLET = (byte) 0xCC;
    private static final byte INS_ISSUE = (byte) 0x40;
    private static final byte INS_KEY = (byte) 0x41;
    private static final byte INS_ID = (byte) 0x42;

    private static byte[] secretkey = null ;

    //Cipher ecipher;
    //Cipher dcipher;

    /** GUI stuff. */
    JTextArea display;
    JPanel button;

    /** GUI stuff. */
    JButton issueButton,keyButton;

    /** The card applet. */
    CardChannel applet;

    /**
     * Constructs the terminal application.
     */
    public PersonalizationTerminal(JFrame parent) {
        buildGUI(parent);
        setEnabled(false);
        addActionListener(this);
        (new CardThread()).start();
    }

    /**
     * Builds the GUI.
     */
    void buildGUI(JFrame parent) {
        setLayout(new BorderLayout());
        display = new JTextArea(DISPLAY_HEIGHT, DISPLAY_WIDTH);
        display.setEditable(false);
        add(new JScrollPane(display), BorderLayout.NORTH);

        issueButton = new JButton("Issue");
        button = new JPanel(new FlowLayout());
        button.add(issueButton);

        add(button, BorderLayout.SOUTH);

        parent.addWindowListener(new CloseEventListener());
    }

    /**
     * Adds the action listener <code>l</code> to all buttons.
     *
     * @param l
     *            the action listener to add.
     */
    public void addActionListener(ActionListener l) {
        issueButton.addActionListener(l);
    }

    class CardThread extends Thread {
        public void run() {
            try {
                TerminalFactory tf = TerminalFactory.getDefault();
                CardTerminals ct = tf.terminals();
                List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);
                if (cs.isEmpty()) {
                    display.setText("No terminals with a card found.");
                    return;
                }

                while (true) {
                    try {
                        for (CardTerminal c : cs) {
                            if (c.isCardPresent()) {
                                try {
                                    Card card = c.connect("*");
                                    try {
                                        applet = card.getBasicChannel();
                                        ResponseAPDU resp = applet.transmit(SELECT_APDU);
                                        if (resp.getSW() != 0x9000) {
                                            throw new Exception("Select failed");
                                        }

                                        // Wait for the card to be removed
                                        while (c.isCardPresent())
                                            ;

                                        break;
                                    } catch (Exception e) {
                                        System.out.println("Card does not contain E-purse Applet!");
                                        sleep(2000);
                                        continue;
                                    }
                                } catch (CardException e) {
                                    display.setText("Couldn't connect to card!");
                                    sleep(2000);
                                    continue;
                                }
                            } else {
                                display.setText("Insert your Card!");
                                sleep(1000);
                                display.setText("");
                                sleep(1000);
                                continue;
                            }
                        }
                    } catch (CardException e) {
                        display.setText("Card status problem!");
                    }
                }
            } catch (Exception e) {
                setEnabled(false);
                display.setText("ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    /**
     * Handles button events.
     *
     * @param ae
     *            event indicating a button was pressed.
     */
    public void actionPerformed(ActionEvent ae) {
        try {
            Object src = ae.getSource();
            if (src instanceof JButton) {
                issue();
            }
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }

    /**
     * Handles 'issue' button event.
     *
     * @throws CardException
     *             if something goes wrong.
     */

    void issue() throws CardException {
        try {
            CommandAPDU capdu = new CommandAPDU(CLA_WALLET, INS_ISSUE,(byte) 0, (byte) 0);
            ResponseAPDU rapdu = applet.transmit(capdu);

            if (rapdu.getSW() != 0x9000) {
                display.append("The card has been already issued\n");
                issueButton.setEnabled(false);
            } else{
               /* File file = new File("key");
                secretkey = new byte[(int) file.length()];
                try {
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        fileInputStream.read(secretkey);
                    } catch (IOException e) {
                        System.out.println("Error Reading The File.\n");
                        e.printStackTrace();
                    }
                } catch (FileNotFoundException e) {
                    System.out.println("File Not Found.\n");
                    e.printStackTrace();
                }*/

                /** Generate ID of the card */
                SecureRandom random = new SecureRandom();
                byte ID[] = new byte[16];
                random.nextBytes(ID);
                System.out.println("Card id: " + toHexString(ID));
                System.out.println("Card id: " + toHexString(ID));


                /** Create the key of the card */
                SecretKey key = new SecretKeySpec(secretkey, 0, secretkey.length, "AES");
                byte[] key_ID = encrypt(ID,key);

                //System.out.println("Card key: " + toHexString(key_ID));

                //System.out.println("Master key: " + toHexString(secretkey));

                /** Sends the key to the card */
                CommandAPDU capdu2 = new CommandAPDU(CLA_WALLET, INS_KEY,(byte) 0,(byte) 0,key_ID, BLOCKSIZE);
                applet.transmit(capdu2);

                /** Sends the id to the card */
                CommandAPDU capdu3 = new CommandAPDU(CLA_WALLET, INS_ID,(byte) 0,(byte) 0,ID, BLOCKSIZE);
                applet.transmit(capdu3);

                display.append("The card is issued\n");
                issueButton.setEnabled(false);
            }
        } catch (Exception e) {
            throw new CardException(e.getMessage());
        }
    }


    static String toHexString(byte[] in) {
        StringBuilder out = new StringBuilder(2*in.length);
        for(int i = 0; i < in.length; i++) {
            out.append(String.format("%02x ", (in[i] & 0xFF)));
        }
        return out.toString().toUpperCase();
    }

//    public byte[] encrypt(byte[] data, SecretKey key) throws Exception {
//        ecipher = Cipher.getInstance("AES/ECB/NoPadding");
//        ecipher.init(Cipher.ENCRYPT_MODE, key);
//
//        byte[] enc = ecipher.doFinal(data);
//        return(enc);
//    }

    /**
     * Creates an instance of this class and puts it inside a frame.
     *
     * @param arg
     *            command line arguments.
     */
    public static void main(String[] arg) {
        JFrame frame = new JFrame(TITLE);
        frame.setSize(new Dimension(300,300));
        frame.setResizable(false);
        Container c = frame.getContentPane();
        PersonalizationTerminal panel = new PersonalizationTerminal(frame);
        c.add(panel);
        frame.addWindowListener(new CloseEventListener());
        frame.pack();
        frame.setVisible(true);
    }
}

/**
 * Class to close window.
 */
class CloseEventListener extends WindowAdapter {
    public void windowClosing(WindowEvent we) {
        System.exit(0);
    }
}
