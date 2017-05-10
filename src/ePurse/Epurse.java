package ePurse;

import javacard.framework.*;


/**
 * @noinspection ClassNamePrefixedWithPackageName, ImplicitCallToSuper, MethodOverridesStaticMethodOfSuperclass, ResultOfObjectAllocationIgnored
 */
public class Epurse extends Applet implements ISO7816 {

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

    private final static byte SELECT = (byte) 0xA4;

    private final static short UNKNOWN_INSTRUCTION_ERROR = (short) 1;

    private final byte[] tmp;
    private final byte[] appletAID;

    public Epurse() {
        tmp = new byte[128];
        appletAID = new byte[8];
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Epurse();
    }

    /**
     * @noinspection UnusedDeclaration
     */
    public void process(APDU apdu) {
        AID aid = JCSystem.getAID();
        byte[] buffer = apdu.getBuffer();
        // Store AID in appletAID byte array
        aid.getBytes(appletAID, (short) 0);
        byte cla = buffer[OFFSET_CLA];  // Class byte
        byte ins = buffer[OFFSET_INS];  // Instruction byte
        switch (ins) {
            //Verification APDUs:
            case SELECT:
                // Check whether the API send to us matches this Applet's AID
                short readCount = apdu.setIncomingAndReceive();
//                System.out.println("Readcount: " + readCount);
                Util.arrayCopy(buffer, OFFSET_CDATA, tmp, (short) 0, readCount);
//                System.out.println("Received AID:\t" + DatatypeConverter.printHexBinary(tmp));
//                System.out.println("Applet AID: \t" + DatatypeConverter.printHexBinary(appletAID));
//                System.out.println("APDU: " + DatatypeConverter.printHexBinary(buffer));
                if (Util.arrayCompare(tmp, (short) 0, appletAID, (short) 0, (short) appletAID.length) == (byte) 0) {
                    // SELECT succeeded
//                    System.out.println("Success!");
                    short le = apdu.setOutgoing();
                    if (le < (short) 2) {
                        ISOException.throwIt(SW_WRONG_LENGTH);
                        return;
                    }
                    apdu.setOutgoingLength((short) 3);
                    // build response data in apdu.buffer[ 0.. outCount-1 ];
                    buffer[0] = (byte) 1;
                    buffer[1] = (byte) 2;
                    buffer[3] = (byte) 3;
                    apdu.sendBytes((short) 0, (short) 3);
                    // return good complete status 90 00
                } else {
                    ISOException.throwIt(SW_APPLET_SELECT_FAILED);
                }
                break;
            case VERIFICATION_HI:
                //TODO:
            case VERIFICATION_V:
                //TODO:
                // Personalization APDUs:
                //Todo: check whether you are in the personalization state
            case PERSONALIZATION_HI:
                //Todo:
            case PERSONALIZATION_DATES:
                //Todo:
            case PERSONALIZATION_NEW_PIN:
                //TODO:

                //Decommissioning APDUs:
            case DECOMMISSIONING_HI:
                //Todo:
            case DECOMMISSIONING_CLEAR:
                //Todo:

                //Reloading APDUs:
            case RELOADING_HI:
                //TODO:
            case RELOADING_UPDATE:
                //TODO:

                //Crediting APDUs:
            case CREDIT_HI:
                //TODO:
            case CREDIT_COMMIT_PIN:
                //TODO:
            case CREDIT_COMMIT_NO_PIN:
                //TODO:
            case CREDIT_NEW_BALANCE:
                //TODO:

            default:
                throw new ISOException(UNKNOWN_INSTRUCTION_ERROR);
        }
    }

}