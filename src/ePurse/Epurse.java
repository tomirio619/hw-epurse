package ePurse;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.*;


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

    private final static short UNKNOWN_INSTRUCTION_ERROR = (short) 1;

    public Epurse() {
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Epurse();
    }

    /**
     * @noinspection UnusedDeclaration
     */
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];
        switch (ins){
            //Verification APDUs:
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