package ePurse;

import com.licel.jcardsim.crypto.ECPrivateKeyImpl;
import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.Signature;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;


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
    private final static byte KEYPAIR_PRIVATE = (byte) 0x43;


    private final static byte SELECT = (byte) 0xA4;

    private final static short UNKNOWN_INSTRUCTION_ERROR = (short) 1;

    private byte[] transientBuffer;

    private javacard.security.ECPrivateKey privateKey;
    private Signature signature;

    public Epurse() {
        transientBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
        privateKey = (javacard.security.ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Epurse();
    }

    public boolean select(){
        return true;
    }

    /**
     *
     * @param number the number to increment
     * @param offset from which index it should write the random number to the transcient buffer
     */
    private void incrementNumberAndStore(short number, short offset){
        number += 1;
        transientBuffer[offset] = (byte) (number >> 8);
        transientBuffer[offset+1] = (byte) number;
    }

    /**
     * Big endian
     * @param msb
     * @param lsb
     * @param offset from which index it should write the random number to the transcient buffer
     */
    private void incrementNumberAndStore(byte msb, byte lsb, short offset){
        short number = Util.makeShort(msb, lsb);
        number += 1;
        transientBuffer[offset] = (byte) (number >> 8);
        transientBuffer[offset+1] = (byte) number;
    }



    /**
     * @noinspection UnusedDeclaration
     */
    public void process(APDU apdu) {

        if (selectingApplet()){
            return;
        }

        AID aid = JCSystem.getAID();
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[OFFSET_CLA];  // Class byte
        byte ins = buffer[OFFSET_INS];  // Instruction byte

        switch (ins) {
            //Init phase:
            case KEYPAIR_PRIVATE: {
                //Todo: check whether the state allows for personalisation

                short datalength = (short) buffer[OFFSET_LC];
                Util.arrayCopy(buffer, OFFSET_CDATA, transientBuffer, (short) 0, datalength);
                privateKey.setS(transientBuffer, (short) 0, datalength);
                signature.init(privateKey, Signature.MODE_SIGN);
                transientBuffer[0] = (byte) 42;
                short length = signature.sign(transientBuffer, (short) 0, (short) 1, transientBuffer, (short) 1);
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) (1 + length));
                apdu.sendBytesLong(transientBuffer, (short) 0, (short) (1 + length));

                //Todo: mark in the state that the card does not accept any new keys
                break;
                //Verification APDUs:
            } case VERIFICATION_HI:
                //Increment the received number
                short datalength = (short) buffer[OFFSET_LC];
                Util.arrayCopy(buffer, OFFSET_CDATA, transientBuffer, (short) 0, datalength);
                incrementNumberAndStore(transientBuffer[0], transientBuffer[1], (short) 0);

                //Sign the response
                transientBuffer[2] = (byte) 42;
//                signature.init(keypair.getPrivate(), Signature.MODE_SIGN);
                short signatureSize = signature.sign(transientBuffer, (short) 0, (short) 3, transientBuffer, (short) 4);

                //Send the response
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) 2);
                apdu.sendBytesLong(transientBuffer, (short) 0, (short) (3+signatureSize));
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

}