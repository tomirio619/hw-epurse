package ePurse;

import com.sun.imageio.plugins.jpeg.JPEG;
import javacard.framework.*;
import javacard.security.*;

/**
 * @noinspection ClassNamePrefixedWithPackageName, ImplicitCallToSuper, MethodOverridesStaticMethodOfSuperclass, ResultOfObjectAllocationIgnored
 */
public class Epurse extends Applet implements ISO7816 {

    /**
     * Instruction bytes
     */
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
    private final static byte KEYPAIR_PRIVATE = (byte) 0x43;
    private final static byte KEYPAIR_PRIVATE_RSA = (byte) 0x45;

    private final static byte DECRYPTION_KEY = (byte) 0x44;

    private final static byte SELECT = (byte) 0xA4;

    private final static short UNKNOWN_INSTRUCTION_ERROR = (short) 1;

    /**
     * State bytes
     */
    private final static byte STATE_RAW = 0;
    private final static byte STATE_INITIALIZED = 1;
    private final static byte STATE_PERSONALIZED = 2;

    /**
     * Transient buffer
     */
    private byte[] transientBuffer;

    /**
     * Cryptographic primitives
     */
    private Signature signingKey;

    private Signature signature;

    private RSAPublicKey pubKey;

    private RSAPrivateKey privKey;

    private RSAPrivateKey decryptionKey;

    private byte[] headerBuffer;

    /**
     * Constructor
     */
    public Epurse() {
        transientBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
        headerBuffer = JCSystem.makeTransientByteArray((short) 5, JCSystem.CLEAR_ON_RESET);
        pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
                KeyBuilder.LENGTH_RSA_1024, false);
        privKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                KeyBuilder.LENGTH_RSA_1024, false);
        signingKey = Signature.getInstance(KeyPair.ALG_RSA, false);
        register();
    }

    /**
     * Installs the applet
     *
     * @param bArray
     * @param bOffset
     * @param bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Epurse();
    }

    public boolean select() {
        return true;
    }

    /**
     * @param number the number to increment
     * @param offset from which index it should write the random number to the transcient buffer
     */
    private void incrementNumberAndStore(short number, short offset) {
        number += 1;
        transientBuffer[offset] = (byte) (number >> 8);
        // transientBuffer[offset+(short)1] = (byte) number;
    }

    /**
     * Big endian
     *
     * @param msb The most significant byte of the short
     * @param lsb The least significant byte of the short
     * @param offset from which index it should write the random number to the transcient buffer
     */
    private void incrementNumberAndStore(byte msb, byte lsb, short offset) {
        short number = Util.makeShort(msb, lsb);
        number += 1;
        transientBuffer[offset] = (byte) (number >> 8);
        //transientBuffer[offset+((short)1)] = (byte) number;
    }


    /**
     * Sign a payload starting from the offset with the length of the payload
     *
     * @param source The data to sign
     * @param sourceOffset The offset
     * @param sourceLength The length
     * @param dest The destination
     * @param destOffset The destination offset
     */
    private short sign(byte[] source, short sourceOffset, short sourceLength, byte[] dest, short destOffset) {
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signature.init(privKey, Signature.MODE_SIGN);
        return signature.sign(source, sourceOffset, sourceLength, dest, destOffset);
    }


    /**
     * @noinspection UnusedDeclaration
     */
    public void process(APDU apdu) {

        if (selectingApplet()) {
            return;
        }

        // Store APDU header in global transient array
        Util.arrayCopy(apdu.getBuffer(), (short) 0, headerBuffer, (short) 0, (short) 5);
        // Handle instructions
        switch (headerBuffer[OFFSET_INS]) {
            //Init phase:
            case KEYPAIR_PRIVATE_RSA: {
                insKeypairPrivateRSA(apdu);
                break;
            }
            case KEYPAIR_PRIVATE: {
                insKeyPairPrivate(apdu);
                break;
            }
            case DECRYPTION_KEY: {
                insDecryptionKey(apdu);
                break;
                //Verification APDUs:
            }
            case VERIFICATION_HI:
                insVerificationHigh(apdu);
                break;
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

    /**
     * Read apdu buffer and store into a different array
     * @param apdu The apdu
     * @param dest The destination array
     * @param offset The offset within the destination array
     * @param length The length
     */
    private void readBuffer(APDU apdu, byte[] dest, short offset,
                            short length) {
        byte[] buf = apdu.getBuffer();
        short readCount = apdu.setIncomingAndReceive();
        short i = 0;
        Util.arrayCopy(buf, OFFSET_CDATA, dest, offset, readCount);
        while ((short) (i + readCount) < length) {
            i += readCount;
            offset += readCount;
            readCount = (short) apdu.receiveBytes(OFFSET_CDATA);
            Util.arrayCopy(buf, OFFSET_CDATA, dest, offset, readCount);
        }
    }

    /**
     *
     * @param apdu
     */
    private void insKeypairPrivateRSA(APDU apdu) {
        boolean isModulus = headerBuffer[OFFSET_P1] == (byte) 0;
        if (isModulus) {
            readBuffer(apdu, transientBuffer, (short) 0, headerBuffer[OFFSET_LC]);
            privKey.setModulus(transientBuffer, (short) 0, headerBuffer[OFFSET_LC]);
        } else {
            readBuffer(apdu, transientBuffer, (short) 0, headerBuffer[OFFSET_LC]);
            privKey.setExponent(transientBuffer, (short) 0, headerBuffer[OFFSET_LC]);
        }
    }

    /**
     *
     * @param apdu
     */
    private void insKeyPairPrivate(APDU apdu) {
        //Todo: check whether the state allows for personalisation
        byte datalength = headerBuffer[OFFSET_LC];

        //After setIncomingAndReceive data is available in buffer RD
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if (byteRead != datalength) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        Util.arrayCopy(apdu.getBuffer(), OFFSET_CDATA, transientBuffer, (short) 0, datalength);

        // inform system that the applet has finished
        // processing the command and the system should
        // now prepare to construct a response APDU
        // which contains data field SD
        short le = apdu.setOutgoing();

        //informs the CAD the actual number of bytes ret

        transientBuffer[0] = (byte) 42;
        short length = sign(transientBuffer, (short) 0, (short) 1, transientBuffer, (short) 1);
        apdu.setOutgoingLength((short) (1 + length));
        apdu.sendBytesLong(transientBuffer, (short) 0, (short) (1 + length));
        //Todo: mark in the state that the card does not accept any new keys
    }

    /**
     *
     * @param apdu
     */
    private void insDecryptionKey(APDU apdu) {
        short datalength = (short) headerBuffer[OFFSET_LC];
        Util.arrayCopy(apdu.getBuffer(), OFFSET_CDATA, transientBuffer, (short) 0, datalength);
        short exponentLength = headerBuffer[OFFSET_P1];
        short modulusLength = headerBuffer[OFFSET_P2];

        decryptionKey.setExponent(transientBuffer, (short) 0, exponentLength);
        decryptionKey.setModulus(transientBuffer, (short) (exponentLength + 1), modulusLength);
    }

    /**
     *
     * @param apdu
     */
    private void insVerificationHigh(APDU apdu) {
        //Increment the received number
        short datalength = (short) headerBuffer[OFFSET_LC];
        Util.arrayCopy(apdu.getBuffer(), OFFSET_CDATA, transientBuffer, (short) 0, datalength);
        incrementNumberAndStore(transientBuffer[0], transientBuffer[1], (short) 0);

        //Sign the response
        transientBuffer[2] = (byte) 42;
//                signature.init(keypair.getPrivate(), Signature.MODE_SIGN);

        short signatureSize = signature.sign(transientBuffer, (short) 0, (short) 3, transientBuffer, (short) 4);

        //Send the response
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 2);
        apdu.sendBytesLong(transientBuffer, (short) 0, (short) (3 + signatureSize));

    }

}