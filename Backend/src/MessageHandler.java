/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ResultSet;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author root
 */
public class MessageHandler {

    public static final String privateModulusBackend = "88b6e95aa01079580e95e47f4ad703abe6d1be8901277f31ec3095660b807b62c28009ce46fef4a43fdabcc2fa21f35463529589b970131090fd232e8d9cfea1cae873c9aeaa017c91a9d0079694eec25c58b884d042356e08a47ab2accff9bd8b61abdb0d2be96d5d71fef79176098cb31ef04508eea31e08e94c2f205c0a29";
    public static final String privateExponentBackend = "53d7d944bae55f85a16c4bb5c5301810547e4d5bb85980a81d31ae6de69fe50bac3cd9c6a7c3b44506e41edf74875db36336427f343a8776a1749d1eefba586dfac2e59e1b7d82c92d6846bb632ad83613bdac5ebb5d76f46d6be3a7563051224139738f6e524b6b9181f4e0e6e39902d4da9d4339c53507599e8b34d73211";
    public static final String publicModulusBackend = "88b6e95aa01079580e95e47f4ad703abe6d1be8901277f31ec3095660b807b62c28009ce46fef4a43fdabcc2fa21f35463529589b970131090fd232e8d9cfea1cae873c9aeaa017c91a9d0079694eec25c58b884d042356e08a47ab2accff9bd8b61abdb0d2be96d5d71fef79176098cb31ef04508eea31e08e94c2f205c0a29";
    public static final String publicExponentBackend = "65537";
    boolean queryError;
    private byte[] message;
    private Channel ch;
    private Database db;
    private byte[] signature;
    private short messageCode, nonce, terminalID, cardID;
    private boolean hasMessage;
    private RSAPrivateKey priv;
    private byte[] q_pubkey;
    private String q_cardholder;
    private short q_balance;
    private boolean q_blocked;
    private Date create_date;
    private Date expiration_date;
    private String q_terminalkind;
    private byte[] q_terminalpubkey;
    private boolean q_terminalvalid;
    private RSAPublicKey pTerminal, pCard;
    private String q_pubkey_string;
    private String q_terminalpubkey_string;

    public MessageHandler(Channel ch, byte[] message, Database db) {
        this.message = message;
        this.ch = ch;
        this.db = db;
        this.priv = getPrivateKey();
        parseMessage();
    }

    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for (byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    private void parseMessage() {
        queryError = false;
        messageCode = bytesToShort(Arrays.copyOfRange(message, 0, 2));
        message = Arrays.copyOfRange(message, 2, message.length);
        handleMessage();
        if (queryError) {
            error(6);
        }
    }

    private void handleMessage() {
        switch (messageCode) {
            case 1:
                verification();
                break;
            case 2:
                personalization();
                break;
            case 3:
                decommisionCard();
                break;
            case 4:
                reloadCard();
                break;
            case 5:
                creditCard();
                break;
            default:
                System.out.println("ERROR: MESSAGE CODE NOT FOUND");
        }
    }

    private void verification() {
        // *CA* NONCE (2) | Card_id (2) | SigCA(128) | NONCE2 (2) | Terminal_id (2) | SigTA(128)
        byte[] CA = Arrays.copyOfRange(message, 0, 4 + 128);
        byte[] TA = Arrays.copyOfRange(message, 4 + 128, message.length);
        byte[] CA_noS = Arrays.copyOfRange(CA, 0, 4);
        byte[] TA_noS = Arrays.copyOfRange(TA, 0, 4);
        short nonce1 = bytesToShort(Arrays.copyOfRange(CA, 0, 2));
        cardID = bytesToShort(Arrays.copyOfRange(CA, 2, 4));
        short nonce2 = bytesToShort(Arrays.copyOfRange(TA, 0, 2));
        terminalID = bytesToShort(Arrays.copyOfRange(TA, 2, 4));
        byte[] sigCA = Arrays.copyOfRange(CA, 4, 4 + 128);
        byte[] sigTA = Arrays.copyOfRange(TA, 4, 4 + 128);
        terminalQuery();
        cardQuery();

        if (!queryError) {
            q_pubkey = hexStringToByteArray(q_pubkey_string);
            q_terminalpubkey = hexStringToByteArray(q_terminalpubkey_string);
            pCard = keyFromEncoded(q_pubkey);
            pTerminal = keyFromEncoded(q_terminalpubkey);
            if (!Sign.checkSignature(TA_noS, sigTA, pTerminal)) {
                error(3);
            } else if (nonce1 + 1 != nonce2) {
                error(4);
            } else if (checkForErrors(CA_noS, sigCA, pCard)) {
            } else {
                // Nonce + exponentCard + modulusCard + exponentTerminal + modulusTerminal + signature
                byte[] pCard_encoded = pCard.getEncoded();
                byte[] pTerm_exp = pTerminal.getPublicExponent().toByteArray();
                byte[] pTerm_mod = getBytes(pTerminal.getModulus());
                byte[] messageToSign = new byte[2 + pCard_encoded.length + pTerm_exp.length + pTerm_mod.length];
                System.arraycopy(shortToBytes((short) (nonce1 + 2)), 0, messageToSign, 0, 2);
                int writeIndex = 2;
                System.arraycopy(pCard_encoded, 0, messageToSign, writeIndex, pCard_encoded.length);
                writeIndex += pCard_encoded.length;
                System.arraycopy(pTerm_exp, 0, messageToSign, writeIndex, pTerm_exp.length);
                writeIndex += pTerm_exp.length;
                System.arraycopy(pTerm_mod, 0, messageToSign, writeIndex, pTerm_mod.length);
                byte[] signatureReturn = Sign.createSignature(priv, messageToSign);
                byte[] returnMessage = new byte[messageToSign.length + signatureReturn.length];
                System.arraycopy(messageToSign, 0, returnMessage, 0, messageToSign.length);
                System.arraycopy(signatureReturn, 0, returnMessage, messageToSign.length, signatureReturn.length);
                ch.sendMessage(returnMessage);
            }
        }

    }

    private void personalization() {
        byte[] new_card_pk = Arrays.copyOfRange(message, 0, 162);
        byte[] arrayTime = Arrays.copyOfRange(message, 162, 162 + 4);
        int timeSeconds = ((0xFF & arrayTime[0]) << 24) | ((0xFF & arrayTime[1]) << 16) |
                ((0xFF & arrayTime[2]) << 8) | (0xFF & arrayTime[3]);
        Date date = new Date(timeSeconds * 1000L); // *1000 is to convert seconds to milliseconds
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); // the format of your date
        String formattedDate = sdf.format(date);
        ch.sendMessage(shortToBytes(makeCard(new_card_pk, formattedDate)));
    }

    private void decommisionCard() {
        short nonce1 = bytesToShort(Arrays.copyOfRange(message, 0, 2));
        cardID = bytesToShort(Arrays.copyOfRange(message, 2, 4));
        byte[] signatureCheck = Arrays.copyOfRange(message, 4, 128 + 4);
        byte[] messageNoSignature = Arrays.copyOfRange(message, 0, 4);
        cardQuery();
        if (!queryError) {
            q_pubkey = hexStringToByteArray(q_pubkey_string);
            pCard = keyFromEncoded(q_pubkey);
            if (!checkForErrors(messageNoSignature, signatureCheck, pCard)) {
                deleteCard(cardID);
                byte[] messageToSign = new byte[4];
                System.arraycopy(shortToBytes((short) (nonce1 + 1)), 0, messageToSign, 0, 2);
                System.arraycopy(shortToBytes(cardID), 0, messageToSign, 2, 2);
                byte[] sig = Sign.createSignature(priv, messageToSign);
                byte[] returnMessage = new byte[4 + 128];
                System.arraycopy(messageToSign, 0, returnMessage, 0, 4);
                System.arraycopy(sig, 0, returnMessage, 4, 128);
                ch.sendMessage(returnMessage);
            }
        }
    }

    private void reloadCard() {

        //MESSAGECODE || TID || AMOUNT || AMOUNTSIGNED(TERMINAL) || NONCE || CARDID || SIGNED(CARD)
        terminalID = bytesToShort(Arrays.copyOfRange(message, 0, 2));
        short amount = bytesToShort(Arrays.copyOfRange(message, 2, 4));
        byte[] signatureAmount = Arrays.copyOfRange(message, 4, 4 + 128);
        byte[] terminalMessage = Arrays.copyOfRange(message, 0, 4);
        short nonce1 = bytesToShort(Arrays.copyOfRange(message, 132, 132 + 2));
        cardID = bytesToShort(Arrays.copyOfRange(message, 134, 134 + 2));
        byte[] signatureCheck = Arrays.copyOfRange(message, 136, message.length);
        byte[] messageNoSignature = Arrays.copyOfRange(message, 132, message.length - 128);
        terminalQuery();
        cardQuery();
        if (!queryError) {
            q_pubkey = hexStringToByteArray(q_pubkey_string);
            q_terminalpubkey = hexStringToByteArray(q_terminalpubkey_string);
            pCard = keyFromEncoded(q_pubkey);
            pTerminal = keyFromEncoded(q_terminalpubkey);
            short newBalance = (short) (q_balance + Math.abs(amount));
            if (checkForErrors(messageNoSignature, signatureCheck, pCard)) {
                System.out.println("Card fail");
            } else if (!Sign.checkSignature(terminalMessage, signatureAmount, pTerminal)) {
                System.out.println("terminal fail");
                error(3);
            } else if (newBalance < 0) {
                error(5);
            } else {
                if (newBalance != q_balance) updateBalance(newBalance, cardID);
                byte[] messageToSign = new byte[4];
                System.arraycopy(shortToBytes((short) (nonce1 + 1)), 0, messageToSign, 0, 2);
                System.arraycopy(shortToBytes(newBalance), 0, messageToSign, 2, 2);
                byte[] sign = Sign.createSignature(priv, messageToSign);
                byte[] returnArray = new byte[4 + 128];
                System.arraycopy(messageToSign, 0, returnArray, 0, 4);
                System.arraycopy(sign, 0, returnArray, 4, 128);
                ch.sendMessage(returnArray);
            }
        }
    }

    private void creditCard() {
        short nonce1 = bytesToShort(Arrays.copyOfRange(message, 0, 2));
        cardID = bytesToShort(Arrays.copyOfRange(message, 2, 4));
        short amount = bytesToShort(Arrays.copyOfRange(message, 4, 6));
        byte[] signatureCheck = Arrays.copyOfRange(message, 6, 128 + 6);
        byte[] messageNoSignature = Arrays.copyOfRange(message, 0, 6);
        cardQuery();
        if (!queryError) {
            q_pubkey = hexStringToByteArray(q_pubkey_string);
            pCard = keyFromEncoded(q_pubkey);
            System.out.println(q_balance);
            System.out.println(amount);
            short new_balance = (short) (q_balance - Math.abs(amount));
            if (checkForErrors(messageNoSignature, signatureCheck, pCard)) {
            } else if (new_balance < 0) {
                error(5);
            } else {
                updateBalance(new_balance, cardID);
                logPayment(cardID, amount, q_balance, new_balance, bytesToHex(signatureCheck));
                byte[] messageToSign = shortToBytes((short) (nonce1 + 1));
                byte[] sig = Sign.createSignature(priv, messageToSign);
                byte[] returnMessage = new byte[2 + 128];
                System.arraycopy(messageToSign, 0, returnMessage, 0, 2);
                System.arraycopy(sig, 0, returnMessage, 2, 128);
                ch.sendMessage(returnMessage);
            }
        }

    }

    public short bytesToShort(byte[] bytes) {
        return (short) (((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF));
    }

    public byte[] shortToBytes(short x) {
        byte[] arr = new byte[]{(byte) (x >>> 8), (byte) (x & 0xFF)};
        return arr;
    }

    private RSAPublicKey keyFromEncoded(byte[] encodedKey) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            RSAPublicKey pubk = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedKey));
            return pubk;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            error(6);
            Logger.getLogger(MessageHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private RSAPrivateKey getPrivateKey() {
        BigInteger modulus = new BigInteger(privateModulusBackend, 16);
        BigInteger exponent = new BigInteger(privateExponentBackend, 16);

        RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, exponent);

        KeyFactory factory = null;
        try {

            factory = KeyFactory.getInstance("RSA");
            // Create the RSA private and public keys
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            RSAPrivateKey privat = (RSAPrivateKey) factory.generatePrivate(privateSpec);
            return privat;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            error(6);
            e.printStackTrace();
        }
        return null;
    }

    private void terminalQuery() {
        String terminalKeyQuery = "SELECT * FROM `Terminals` WHERE (`terminal_id`=" + terminalID + ")";
        ResultSet rs = db.executeQuery(terminalKeyQuery);
//        printRs(rs);
        try {
            while (rs.next()) {
                q_terminalkind = rs.getString("terminal_kind");
                q_terminalpubkey_string = rs.getString("public_key");
                q_terminalvalid = rs.getBoolean("valid");
            }
            if (q_terminalpubkey_string == null) {
                queryError = true;
            }
        } catch (Exception ex) {
            error(6);
            Logger.getLogger(MessageHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void cardQuery() {
        String cardQuery = "SELECT * FROM `Cards` WHERE (`card_id`=" + cardID + ")";
        ResultSet rs = db.executeQuery(cardQuery);
        try {

            while (rs.next()) {
                q_pubkey_string = rs.getString("public_key");
                q_cardholder = rs.getString("card_holder");
                q_balance = (short) rs.getInt("balance");
                q_blocked = rs.getBoolean("blocked");
                create_date = rs.getDate("create_date");
                expiration_date = rs.getDate("expiration_date");
            }
            if (q_pubkey_string == null) {
                queryError = true;
            }

        } catch (Exception ex) {
            error(6);
            Logger.getLogger(MessageHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private short makeCard(byte[] pubKey, String expire) {
        short card_id = 0;
        String queryUpdate =
                "INSERT INTO Cards (card_holder, public_key, balance, blocked, expiration_date) VALUES ('bla','" + bytesToHex(pubKey) + "','0', '0','" + expire + "')";
        String queryID =
                "SELECT LAST_INSERT_ID() as last_id;";

        db.updateQuery(queryUpdate);
        ResultSet rs = db.executeQuery(queryID);
        try {
            while (rs.next()) {
                card_id = (short) rs.getInt("last_id"); // IS ID EEN SHORT?
            }
        } catch (Exception ex) {

        }
        return card_id;
    }

    private void deleteCard(short card_id) {
        String queryUpdate = "UPDATE Cards SET blocked=" + 1 + " WHERE card_id=" + card_id;
        db.updateQuery(queryUpdate);
    }

    private void updateBalance(short new_balance, short card_id) {
        String queryUpdate = "UPDATE Cards SET balance=" + new_balance + " WHERE card_id=" + card_id;
        db.updateQuery(queryUpdate);
    }

    private void logPayment(short card_id, short amount, short old_balance, short new_balance, String signature) {
        String query = "INSERT INTO Transactions (card_id, amount, old_balance, new_balance, signature) VALUES ('" +
                card_id + "','" +
                amount + "','" +
                old_balance + "','" +
                new_balance + "','" +
                signature + "')";
        db.updateQuery(query);
    }

    private void error(int errorCode) {
        //CODE 1: CARD BLOCKED
        //CODE 2: CARD EXPIRED
        //CODE 3: SIGNATURE FAIL
        //CODE 4: NONCE FAIL
        //CODE 5: NEGATIVE AMOUNT
        //CODE 6: BACKEND ERROR
        ch.sendMessage(intToBytes(errorCode));
        System.out.println("ERRORCODE: " + errorCode);
    }

    byte[] intToBytes(int i) {
        byte[] result = new byte[4];
        result[0] = (byte) (i >> 24);
        result[1] = (byte) (i >> 16);
        result[2] = (byte) (i >> 8);
        result[3] = (byte) (i /*>> 0*/);
        return result;
    }

    private boolean checkForErrors(byte[] message, byte[] signature, RSAPublicKey pk) {
        boolean error = false;
        if (q_blocked) {
            error = true;
            error(1);
        } else if (expired(expiration_date)) {
            error = true;
            error(2);
        } else if (!Sign.checkSignature(message, signature, pk)) {
            error = true;
            error(3);
        }
        return error;
    }

    byte[] getBytes(BigInteger big) {
        byte[] data = big.toByteArray();
        if (data[0] == 0) {
            byte[] tmp = data;
            data = new byte[tmp.length - 1];
            System.arraycopy(tmp, 1, data, 0, tmp.length - 1);
        }
        return data;
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private boolean expired(Date expiration_date) {
        Date today = new Date();
        return expiration_date.before(today);
    }
}
