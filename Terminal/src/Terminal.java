import com.sun.xml.internal.bind.v2.runtime.unmarshaller.ValuePropertyLoader;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;


/**
 * Created by Tomirio on 9-5-2017.
 */
public class Terminal {


    private static final String APPLET_AID = "a04041424344454610"; //01";
    private static final byte CLASS = (byte) 0xB0;
    private final static byte VERIFICATION_HI = (byte) 0x41;
    private final static byte SEND_KEYPAIR = (byte) 0x43;
    private final static byte SEND_KEYPAIR_RSA = (byte) 0x45;
    private final static byte PERSONALIZATION_NEW_PIN = (byte) 0x32;
    private final static byte PERSONALIZATION_HI = (byte) 0x30;
    private final static byte PERSONALIZATION_DATES = (byte) 0x31;
    private final static byte VERIFICATION_V = (byte) 0x42;
    private final static byte VERIFICATION_S = (byte) 0x47;
    private final static byte BACKEND_KEY = (byte) 0x46;
    private final static byte DECOMMISSIONING_HI = (byte) 0x33;
    private final static byte DECOMMISSIONING_CLEAR = (byte) 0x34;

    private final static byte RELOADING_HI = (byte) 0x35;
    private final static byte RELOADING_UPDATE = (byte) 0x36;

    private final static byte CREDIT_HI = (byte) 0x37;
    private final static byte CREDIT_COMMIT_PIN = (byte) 0x38;
    private final static byte CREDIT_COMMIT_NO_PIN = (byte) 0x39;
    private final static byte CREDIT_NEW_BALANCE = (byte) 0x40;


    private RSAPublicKey publicKeyBackend;
    private RSAPrivateKey privateKeyBackend;

    private RSAPublicKey publicKeyTerminal;
    private RSAPrivateKey privateKeyTerminal;

    private SecureRandom secureRandom;
    private byte[] terminalId = new byte[]{0x33, 0x55};

    private RSAPublicKey publicKeyCard;


    public Terminal() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        loadBackendKeys();
        loadTerminalKeys();
        secureRandom = new SecureRandom();


        (new TerminalThread()).start();
    }


    void loadBackendKeys()   {

        // Load the key into BigIntegers
        BigInteger modulus = new BigInteger(BackendKeys.privateModulusBackend, 16);
        BigInteger exponent = new BigInteger(BackendKeys.privateExponentBackend, 16);
        BigInteger pubExponent = new BigInteger(BackendKeys.publicExponentBackend);

        // Create private and public key specs
        RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, exponent);
        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubExponent);

        // Create a key factory
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
            // Create the RSA private and public keys
            privateKeyBackend = (RSAPrivateKey) factory.generatePrivate(privateSpec);
            publicKeyBackend = (RSAPublicKey) factory.generatePublic(publicSpec);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }


    }

    private void loadTerminalKeys() {
        //First generate test terminal keypair
        KeyPairGenerator g = null;
        try {
            g = KeyPairGenerator.getInstance("RSA", "BC");
            g.initialize(1024, new SecureRandom());
            java.security.KeyPair pairT = g.generateKeyPair();
            publicKeyTerminal = (RSAPublicKey) pairT.getPublic();
            privateKeyTerminal = (RSAPrivateKey) pairT.getPrivate();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

    }


    class TerminalThread extends Thread  {

        @Override
        public void run() {
            try {



                TerminalFactory tf = TerminalFactory.getDefault();
                CardTerminals ct = tf.terminals();
                List<CardTerminal> cs = ct.list(CardTerminals.State.ALL);//CardTerminals.State.CARD_PRESENT);
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

                                personalizationFull(ch);

                                testTerminalAuth(ch);

                                testReloading(ch);

                                testCrediting(ch);
                                //testDecommissioning(ch);
                                //testSignatureRSA(ch);



                                //testTerminalAuth(ch);

                                //1. Terminal sends Hi
//                            byte[] payload = new byte[2];
//                            new SecureRandom().nextBytes(payload);
//                            short random = Util.makeShort(payload[0], payload[1]);
//                            random = (short) Math.abs(random);
//                            System.out.println(random);
//
//                            CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, payload, 2);
//                            ResponseAPDU responseHi = ch.transmit(hiAPDU);
//                            byte[] randomInc = responseHi.getData();
//                            short incremented = Util.makeShort(randomInc[0], randomInc[1]);
//                            System.out.println(incremented);

                            } catch (Exception e) {
                                e.printStackTrace();
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




        // Send all step personalization
        private void personalizationFull(CardChannel ch) throws CardException, NoSuchAlgorithmException {

            System.out.println("-----Test Personalization-----");
            testSendBackendKey(ch);
            testPersonalizationHi(ch);
            testPesonalizationDates(ch);
            testPin(ch);
        }

        /**
         * Checks whether a nonce (oldNonce1 || oldNonce2) + incrementedBy == nonce (newNonce1 || newNonce2)
         * @param oldNonce1
         * @param oldNonce2
         * @param newNonce1
         * @param newNonce2
         * @param incrementedBy
         * @return
         */
        private boolean isNonceIncrementedBy(byte oldNonce1, byte oldNonce2, byte newNonce1, byte newNonce2, int incrementedBy){
            short old = Util.makeShort(oldNonce1, oldNonce2);
            short newNonce = Util.makeShort(newNonce1, newNonce2);

            return old + incrementedBy == newNonce;
        }

        private byte[] sign(byte[] textToSign){
            Signature signature = null;
            try {
                signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(privateKeyTerminal);
                signature.update(textToSign,0,textToSign.length);
                return signature.sign();
            } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
                e.printStackTrace();
            }

            return null;
        }

        private boolean verify(PublicKey publicKey, byte[] plainText, byte[] signedBytes){
            Signature signature = null;
            try {
                signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initVerify(publicKey);
                signature.update(plainText);
                return signature.verify(signedBytes, 0, signedBytes.length);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
                e.printStackTrace();
                return false;
            }
        }

        private byte[] incrementNonceBy(byte n1, byte n2, int incrementBy){
            short old = Util.makeShort(n1, n2);
            old += incrementBy;

            byte[] nonce = {
                    (byte) (old & 0xff),
                    (byte) ((old >> 8) & 0xff),
            };
            return nonce;
        }

        // the key components and the signature dont fit in an apdu, the idea is send this component
        // firts and then signature of both, modulus and exponent
        public void testTerminalAuth(CardChannel ch) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, CardException {

            System.out.println("-----Test Verification Terminal-----");

            byte [] nonceBytes = new byte[2];
            secureRandom.nextBytes(nonceBytes);
            CommandAPDU hiAPDU = new CommandAPDU(CLASS, VERIFICATION_HI, 0, 0, nonceBytes, 2);
            ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
            System.out.println("VERIFICATION_HI: " + Integer.toHexString(responseAPDU.getSW()));

            byte [] ca = responseAPDU.getData(); // Data Ca{Ca}SKC

            if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], ca[0], ca[1], 1)){
                System.out.println("Nonce not incremented");
            }

            //Create TA
            byte[] TA = new byte[4 + ca.length-4]; //TA is our Id, incremented nonce and the signature part of CA
            byte[] nonce = incrementNonceBy(nonceBytes[0], nonceBytes[1], 1);
            Util.arrayCopy(nonce, (short) 0, TA, (short) 0, (short) 2);
            Util.arrayCopy(terminalId, (short) 0, TA, (short) 2, (short) 2);
            Util.arrayCopy(ca, (short) 4, TA, (short) 4, (short) (ca.length-4));    //Signature part of CA
            byte[] TASigned = sign(TA);

            byte[] CaTaTaSigned = new byte[4+4+TASigned.length]; //We send 4 bytes of Ta, 4 bytes of CA and then the signed part of TA
            Util.arrayCopy(ca, (short) 0, CaTaTaSigned, (short) 0, (short) 4); //Plaintext of CA
            Util.arrayCopy(TA, (short) 0, CaTaTaSigned, (short) 4, (short) 4); //Plaintext of TA
            Util.arrayCopy(TASigned, (short) 0, CaTaTaSigned, (short) 8, (short) TASigned.length);  //Copy everything else

            //Todo: Send everything to the backend

            /*
            FIXME:
            Remove from HERE
             */

            //Sign the public key of the terminal (this id done in the backend)
            byte[] exponentBytes = getBytes(publicKeyTerminal.getPublicExponent());
            byte[] modulusBytes = getBytes(publicKeyTerminal.getModulus());
            byte[] bytesKeyTerm = new byte [modulusBytes.length+exponentBytes.length];
            Util.arrayCopy(exponentBytes,(short)0,bytesKeyTerm,(short)0,(short)exponentBytes.length);
            Util.arrayCopy(modulusBytes,(short)0,bytesKeyTerm,(short)exponentBytes.length,(short)modulusBytes.length);

            byte[] signedKeyTerm = null;
            int lenghtSig=0;
            try {
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(privateKeyBackend);
                signature.update(bytesKeyTerm,0,bytesKeyTerm.length);
                signedKeyTerm = signature.sign();
                lenghtSig = signedKeyTerm.length;

            }catch (Exception e){
                e.printStackTrace();
            }

            /*
            FIXME: Until here
             */


            byte[] v = new byte[5000]; //Received from the backend composed of (plaintext Public key card, plaintext public key terminal, nonce incremented, signature digest of previous)
            int publicKeySize = 1024/8;

            //Check if nonce is properly incremented
            if (! isNonceIncrementedBy(nonce[0], nonce[1], v[2*publicKeySize], v[2*publicKeySize+1], 1)){
                System.out.println("Nonce is not incremented!");
                return;
            }

            //Check if signature is valid
            byte[] vPlaintext = new byte[2*publicKeySize+2];
            Util.arrayCopy(v, (short) 0, vPlaintext, (short) 0, (short) publicKeySize); //Copy public key card plaintext
            Util.arrayCopy(v, (short) publicKeySize, vPlaintext, (short) publicKeySize, (short) publicKeySize ); //Copy public key terminal
            Util.arrayCopy(v, (short) (2*publicKeySize), vPlaintext, (short) (2*publicKeySize), (short) 2); //Copy the nonce


            short signatureSize = (short) (v.length - (2*publicKeySize+2));
            byte[] vSignature = new byte[signatureSize]; //Buffer for signature
            Util.arrayCopy(v, (short) (2*publicKeySize+2), vSignature, (short) 0, signatureSize);

            if (!verify(publicKeyTerminal, vPlaintext, vSignature)) {
                System.out.println("Signature is not valid");
                return;
            }

            //Keep a copy of the public key of the card here
            byte[] publicKeyCardBytes = new byte[publicKeySize];
            Util.arrayCopy(vPlaintext, (short) 0, publicKeyCardBytes, (short) 0, (short) publicKeySize);
            try {
                //Todo: look at whether this is correct. Only works if the RSA public key that has been received was send using the getEncoded() function
                publicKeyCard = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyCardBytes));
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }

            //Send to card


            CommandAPDU capdu;
            ResponseAPDU responsePrivate;

            // Send public key of the terminal extrated from the plaintext
            capdu = new CommandAPDU(CLASS, VERIFICATION_V, (byte) exponentBytes.length, (byte) modulusBytes.length, bytesKeyTerm);
            responsePrivate = ch.transmit(capdu);
            System.out.println("VERIFICATION_V: " + Integer.toHexString(responsePrivate.getSW()));

            // Send the signature
            capdu = new CommandAPDU(CLASS, VERIFICATION_S, (byte) 0, (byte) 0, signedKeyTerm);
            responsePrivate = ch.transmit(capdu);
            System.out.println("VERIFICATION_S: " + Integer.toHexString(responsePrivate.getSW()));
        }



        public void testSendBackendKey(CardChannel ch) throws CardException {
            // Send BE key for verify signatures(this will be done in the personalization)
            byte[] exponentBytesBE = getBytes(publicKeyBackend.getPublicExponent());
            byte[] modulusBytesBE = getBytes(publicKeyBackend.getModulus());
            byte[] bytesKeyBE = new byte [modulusBytesBE.length+exponentBytesBE.length];
            Util.arrayCopy(exponentBytesBE,(short)0,bytesKeyBE,(short)0,(short)exponentBytesBE.length);
            Util.arrayCopy(modulusBytesBE,(short)0,bytesKeyBE,(short)exponentBytesBE.length,(short)modulusBytesBE.length);
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, BACKEND_KEY, (byte) exponentBytesBE.length, (byte) modulusBytesBE.length, bytesKeyBE);
            ResponseAPDU responsePrivate = ch.transmit(capdu);
            System.out.println("BACKEND_KEY: " + Integer.toHexString(responsePrivate.getSW()));

        }

        public void testPersonalizationHi(CardChannel ch) throws CardException, NoSuchAlgorithmException {
            KeyPairGenerator generator  = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            java.security.KeyPair keypair = generator.generateKeyPair();
            RSAPublicKey cardPublickey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey cardPrivateKey = (RSAPrivateKey) keypair.getPrivate();

            //byte [] nonceBytes = new byte[2];
            //secureRandom.nextBytes(nonceBytes);

            byte[] modulus = getBytes(cardPrivateKey.getModulus());
            // Sending modulus private key
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 0, (byte) 0, modulus);
            ResponseAPDU responsePrivate = ch.transmit(capdu);
            System.out.println("PERSONALIZATION_HI private modulus: " + Integer.toHexString(responsePrivate.getSW()));

            // Sending exponent private key
            byte[] exponent = getBytes(cardPrivateKey.getPrivateExponent());
            capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 1, (byte) 0, exponent);
            responsePrivate = ch.transmit(capdu);
            System.out.println("PERSONALIZATION_HI private exponent: " + Integer.toHexString(responsePrivate.getSW()));

            modulus = getBytes(cardPublickey.getModulus());
            capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 2, (byte) 0, modulus);
            responsePrivate = ch.transmit(capdu);
            System.out.println("PERSONALIZATION_HI public modulus: " + Integer.toHexString(responsePrivate.getSW()));

            exponent = getBytes(cardPublickey.getPublicExponent());
            capdu = new CommandAPDU(CLASS, PERSONALIZATION_HI, (byte) 3, (byte) 0, exponent);
            responsePrivate = ch.transmit(capdu);
            System.out.println("PERSONALIZATION_HI public exponent: " + Integer.toHexString(responsePrivate.getSW()));
        }

        private void testPesonalizationDates(CardChannel ch) throws CardException {

            // Get current date unix seconds
            int unixTime = (int)(System.currentTimeMillis() / 1000);
            byte[] personalizedDate = new byte[]{
                    (byte) (unixTime >> 24),
                    (byte) (unixTime >> 16),
                    (byte) (unixTime >> 8),
                    (byte) unixTime

            };// convert date to byte array

            //Expiration date is the current moment + two years in seconds
            int expirationTime = unixTime + 63113851;
            byte[] expirationDate = new byte[]{
                    (byte) (expirationTime >> 24),
                    (byte) (expirationTime >> 16),
                    (byte) (expirationTime >> 8),
                    (byte) expirationTime
            };

            //TODO: Request unique ID from the backend, send public key to the backend

            //Receive id of the card
            byte[] id = new byte[2];
            byte[] dataToSend = new byte[10];//container of data that will be sent to the card

            Util.arrayCopy(id, (short)0, dataToSend, (short)0, (short)2); //copy card id to container
            Util.arrayCopy(personalizedDate, (short)0, dataToSend, (short) 2, (short) 4);//copy date to container
            Util.arrayCopy(expirationDate, (short) 0, dataToSend, (short) 6, (short) 4); //Copy the expiration date to the container

            //send data to the card
            CommandAPDU capdu;
            capdu = new CommandAPDU(CLASS, PERSONALIZATION_DATES, (byte) 0, (byte) 0, dataToSend);
            ResponseAPDU responsePrivate = ch.transmit(capdu);
            System.out.println("PERSONALIZATION_DATES: " + Integer.toHexString(responsePrivate.getSW()));
        }

        private void testPin(CardChannel ch) {
            //Todo: generate PIN at random

            byte[] pin = {1, 2, 3, 4};
            try {
                CommandAPDU capdu;
                capdu = new CommandAPDU(CLASS, PERSONALIZATION_NEW_PIN, (byte) 0, (byte) 0, pin);
                ResponseAPDU responsePrivate = ch.transmit(capdu);
                System.out.println("PERSONALIZATION_NEW_PIN: " + Integer.toHexString(responsePrivate.getSW()));

            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        private void testDecommissioning(CardChannel ch) throws CardException {
            System.out.println("-----Test Decommissioning-----");

            byte [] nonceBytes = new byte[2];
            secureRandom.nextBytes(nonceBytes);

            // This is the signature of the Terminal
            byte[] signedNonce = sign(nonceBytes);
            byte[] nonceSignedNonce = new byte[nonceBytes.length + signedNonce.length];

            System.arraycopy(nonceBytes,0,nonceSignedNonce,0         ,nonceBytes.length);
            System.arraycopy(signedNonce,0,nonceSignedNonce,nonceBytes.length,signedNonce.length);

            CommandAPDU hiAPDU = new CommandAPDU(CLASS, DECOMMISSIONING_HI, 0, 0, nonceSignedNonce, nonceSignedNonce.length);
            ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
            System.out.println("DECOMMISSIONING_HI: " + Integer.toHexString(responseAPDU.getSW()));
            byte [] dataRec = responseAPDU.getData();

            //Check if received nonce has been incremented
            if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], dataRec[0], dataRec[1], 1)){
                System.out.println("Nonce has not been incremeneted");
                return;
            }

            //Verify signature
            byte[] decomNonceIncremented = new byte[2];
            Util.arrayCopy(dataRec, (short) 0, decomNonceIncremented, (short) 0, (short) 2);

            byte[] decomNonceIncrementedSigned = new byte[dataRec.length-2];
            Util.arrayCopy(dataRec, (short) 2, decomNonceIncrementedSigned, (short) 0, (short) (dataRec.length-2));

            if (! verify(publicKeyCard, decomNonceIncremented, decomNonceIncrementedSigned)){
                System.out.println("Signature verification failed");
                return;
            }

            //Todo: send the received message to the backend


            //Receive a message from the backend
            byte[] nonceIncrementedSigned = new byte[2+500]; //Receive this from the backend
            byte[] backendNonceIncremented = new byte[2];
            Util.arrayCopy(nonceIncrementedSigned, (short) 0, backendNonceIncremented, (short) 0, (short) 2); //Copy the plaintext nonce of the backend

            //Check if nonce has been incremented
            if (! isNonceIncrementedBy(nonceBytes[0], nonceBytes[1], backendNonceIncremented[0], backendNonceIncremented[1], 2)){
                System.out.println("Nonce has not been incremented");
                return;
            }

            short signatureSize = (short) (nonceIncrementedSigned.length-2);
            byte[] backendNonceIncrementedSigned = new byte[signatureSize];
            Util.arrayCopy(nonceIncrementedSigned, (short) 2, backendNonceIncrementedSigned, (short) 2, signatureSize);

            //Check if the signature is valid
            if (! verify(publicKeyBackend, backendNonceIncremented, backendNonceIncrementedSigned)){
                System.out.println("Signature is not valid");
                return;
            }

            //Forward this message to the card

            hiAPDU = new CommandAPDU(CLASS, DECOMMISSIONING_CLEAR, 0, 0, nonceIncrementedSigned, nonceIncrementedSigned.length);
            responseAPDU = ch.transmit(hiAPDU);
            System.out.println("DECOMMISSIONING_CLEAR: " + Integer.toHexString(responseAPDU.getSW()));
            
        }


        private void testReloading(CardChannel ch) throws CardException {
            System.out.println("-----Test Reloading-----");

            byte [] nonceBytes = new byte[2];
            secureRandom.nextBytes(nonceBytes);
            short firstShort = Util.makeShort(nonceBytes[0], nonceBytes[1]);

            // This is the signature of the Terminal
            byte[] signedNonce = null;
            try {
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(privateKeyTerminal);
                signature.update(nonceBytes,0,nonceBytes.length);
                signedNonce = signature.sign();

            }catch (Exception e){
                e.printStackTrace();
            }
            byte[] combinedData = new byte[nonceBytes.length + signedNonce.length];

            System.arraycopy(nonceBytes,0,combinedData,0         ,nonceBytes.length);
            System.arraycopy(signedNonce,0,combinedData,nonceBytes.length,signedNonce.length);


            CommandAPDU hiAPDU = new CommandAPDU(CLASS, RELOADING_HI, 0, 0, combinedData, combinedData.length);
            ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
            System.out.println("RELOADING_HI: " + Integer.toHexString(responseAPDU.getSW()));

            //TODO verify signature, send info backend and forward everything to the backend

            byte [] dataRec = responseAPDU.getData();
            short nonce = Util.makeShort(dataRec[0], dataRec[1]);
            // +2 due to the backend increment algo the nonce
            nonce = (short) (nonce+2);
            short id = Util.makeShort(dataRec[2], dataRec[3]);

            //TODO: get correct balance from the backend and increment it with the amount introduced
            short amount = 90;

            byte [] dataToSend = new byte[]{
                    (byte) (nonce >> 8),
                    (byte) nonce,
                    (byte) (id >> 8),
                    (byte) id,
                    (byte) (amount >> 8),
                    (byte) amount

            };

            //TODO sign with terminla key
            byte[] signdeBytes = null;
            try {
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(privateKeyTerminal);
                signature.update(dataToSend,0,dataToSend.length);
                signdeBytes = signature.sign();

            }catch (Exception e){
                e.printStackTrace();
            }

            byte [] bytesApdu = new byte[128+6];
            System.arraycopy(dataToSend,0, bytesApdu,0,6);
            System.arraycopy(signdeBytes,0, bytesApdu,6,128);



            hiAPDU = new CommandAPDU(CLASS, RELOADING_UPDATE, 0, 0, bytesApdu, bytesApdu.length);
            responseAPDU = ch.transmit(hiAPDU);
            System.out.println("RELOADING_UPDATE: " + Integer.toHexString(responseAPDU.getSW()));
            System.out.println("Response: " + DatatypeConverter.printHexBinary(responseAPDU.getData()));




        }

        private void testCrediting(CardChannel ch) throws CardException {

            System.out.println("-----Test Crediting-----");

            byte [] nonceBytes = new byte[2];
            secureRandom.nextBytes(nonceBytes);
            short firstShort = Util.makeShort(nonceBytes[0], nonceBytes[1]);

            // This is the signature of the Terminal
            byte[] signedNonce = null;
            try {
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(privateKeyTerminal);
                signature.update(nonceBytes,0,nonceBytes.length);
                signedNonce = signature.sign();

            }catch (Exception e){
                e.printStackTrace();
            }
            byte[] combinedData = new byte[nonceBytes.length + signedNonce.length];

            System.arraycopy(nonceBytes,0,combinedData,0         ,nonceBytes.length);
            System.arraycopy(signedNonce,0,combinedData,nonceBytes.length,signedNonce.length);


            CommandAPDU hiAPDU = new CommandAPDU(CLASS, CREDIT_HI, 0, 0, combinedData, combinedData.length);
            ResponseAPDU responseAPDU = ch.transmit(hiAPDU);
            System.out.println("CREDIT_HI: " + Integer.toHexString(responseAPDU.getSW()));

            //TODO verify signature, get correct balance from the backend
            short receivedBalance = 50;
            short testAmount = 21;

            if(receivedBalance-testAmount < 0){
                System.out.println("Error negative balance");
                return;
            }

            byte [] dataRec = responseAPDU.getData();
            short nonce = Util.makeShort(dataRec[0], dataRec[1]);
            // +2 due to the backend increment algo the nonce
            nonce = (short) (nonce+2);
            short id = Util.makeShort(dataRec[2], dataRec[3]);
            short newBalance = (short) (receivedBalance - testAmount);

            byte[] dataToSend = null;
            byte instruction;

            if(testAmount>20){
                Scanner scanner = new Scanner(System.in);
                byte[] pinArray = new byte[4];
                String pin = scanner.next();

                for (int i = 0 ; i < pin.length(); i++){
                    pinArray[i] = (byte)  (pin.charAt(i) - 48);
                }

                instruction = CREDIT_COMMIT_PIN;

                dataToSend = new byte[]{
                        (byte) (nonce >> 8),
                        (byte) nonce,
                        (byte) (testAmount >> 8),
                        (byte) testAmount,
                        (byte) (newBalance >> 8),
                        (byte) newBalance,
                        pinArray[0],
                        pinArray[1],
                        pinArray[2],
                        pinArray[3],
                };


            }else{
                instruction = CREDIT_COMMIT_NO_PIN;

                dataToSend = new byte[]{
                        (byte) (nonce >> 8),
                        (byte) nonce,
                        (byte) (testAmount >> 8),
                        (byte) testAmount,
                        (byte) (newBalance >> 8),
                        (byte) newBalance,
                };
            }

            //TODO: get correct balance from the backend and increment it with the amount introduced
            short amount = 90;

            System.out.println(DatatypeConverter.printHexBinary(dataToSend));

            //TODO sign with terminla key
            byte[] signdeBytes = null;
            try {
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                signature.initSign(privateKeyTerminal);
                signature.update(dataToSend,0,dataToSend.length);
                signdeBytes = signature.sign();

            }catch (Exception e){
                e.printStackTrace();
            }

            byte [] bytesApdu = new byte[128+dataToSend.length];
            System.arraycopy(dataToSend,0, bytesApdu,0,dataToSend.length);
            System.arraycopy(signdeBytes,0, bytesApdu,dataToSend.length,128);


            hiAPDU = new CommandAPDU(CLASS, instruction, 0, 0, bytesApdu, bytesApdu.length);
            responseAPDU = ch.transmit(hiAPDU);
            System.out.println("CREDITING_UPDATE: " + Integer.toHexString(responseAPDU.getSW()));
            System.out.println("Response: " + DatatypeConverter.printHexBinary(responseAPDU.getData()));



        }


        /**
         * Gets an unsigned byte array representation of <code>big</code>. A leading
         * zero (present only to hold sign bit) is stripped.
         *
         * @param big a big integer.
         * @return a byte array containing a representation of <code>big</code>.
         */
        byte[] getBytes(BigInteger big) {
            byte[] data = big.toByteArray();
            if (data[0] == 0) {
                byte[] tmp = data;
                data = new byte[tmp.length - 1];
                System.arraycopy(tmp, 1, data, 0, tmp.length - 1);
            }
            return data;
        }

        private void testSignatureRSA(CardChannel ch) {

            System.out.println("-----Test signature RSA-----");


            RSAPublicKey publickey = null;

            RSAPrivateKey privatekey = null;

        /* Generate keypair. */
            try {
                System.out.println("Generating keys...");
                KeyPairGenerator generator = null;

                generator = KeyPairGenerator.getInstance("RSA");

                generator.initialize(1024);
                java.security.KeyPair keypair = generator.generateKeyPair();
                publickey = (RSAPublicKey) keypair.getPublic();
                privatekey = (RSAPrivateKey) keypair.getPrivate();

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

        /* Send private key. */
            try {
                byte[] modulus = getBytes(privatekey.getModulus());

                CommandAPDU capdu;
                capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 0, (byte) 0, modulus);
                ResponseAPDU responsePrivate = ch.transmit(capdu);
                System.out.println("SEND_KEYPAIR modulus: " + Integer.toHexString(responsePrivate.getSW()));


                byte[] exponent = getBytes(privatekey.getPrivateExponent());
                capdu = new CommandAPDU(CLASS, SEND_KEYPAIR_RSA, (byte) 1, (byte) 0, exponent);
                responsePrivate = ch.transmit(capdu);
                System.out.println("SEND_KEYPAIR exponent: " + Integer.toHexString(responsePrivate.getSW()));

                capdu = new CommandAPDU(CLASS, SEND_KEYPAIR, (byte) 0, (byte) 0, 0);
                responsePrivate = ch.transmit(capdu);
                System.out.println("SIGNING Request: " + Integer.toHexString(responsePrivate.getSW()));

                byte[] data = {(byte) 42};

                try {
                    byte[] signedDataTerminal = responsePrivate.getData();
                    Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                    signature.initVerify(publickey);
                    signature.update(signedDataTerminal[0]);
                    boolean ifVerified = signature.verify(signedDataTerminal, (short) 1, (short) 128);
                    System.out.println("Verification " +ifVerified);
                }catch (Exception e){
                    e.printStackTrace();
                }


            } catch (Exception e) {
                e.printStackTrace();
            }


        }


    }
}
