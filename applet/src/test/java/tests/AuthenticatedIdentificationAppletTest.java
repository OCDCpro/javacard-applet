package tests;

import applet.AuthenticatedIdentificationApplet;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.Util;
import org.junit.jupiter.api.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;

/**
 * Tests for the authenticated identification applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Niklas Höher
 */
public class AuthenticatedIdentificationAppletTest extends BaseTest {

    // ===== Configuration options =====
    private final static CardType CARDTYPE = CardType.PHYSICAL; // or: CardType.JCARDSIMLOCAL

    private final static String APPLET_ID = "f000000cdc01";
    private final static String pskHex = "00112233445566778899AABBCCDDEEFF";
    private final static String idHex = "00000000000000000000000000000001";

    // ===== APDU constants =====
    private static final byte CLA_PROPRIETARY = (byte) 0x80;
    private static final byte INS_AUTH_INIT   = (byte) 0x10;
    private static final byte INS_AUTH        = (byte) 0x11;
    private static final byte INS_GET_ID      = (byte) 0x12;

    public AuthenticatedIdentificationAppletTest() {
        super(APPLET_ID, AuthenticatedIdentificationApplet.class, CARDTYPE);
    }

    @Test
    public void testCorrectProtocolFlow() throws Exception {
        final byte[] psk = Util.hexStringToByteArray(pskHex);
        final byte[] id = Util.hexStringToByteArray(idHex);
        // Install data: AID length = 0, Control data length = 0, Applet data length = psk.length + id.length
        final byte[] installData = Util.hexStringToByteArray("0000" + Integer.toHexString(psk.length + id.length) + pskHex + idHex);

        // Initialize connection to card / simulator
        final CardManager cardManager = connect(installData);

        // ===== Step 1: AUTH_INIT =====
        CommandAPDU authInitCmd = new CommandAPDU(CLA_PROPRIETARY, INS_AUTH_INIT, 0x00, 0x00);
        ResponseAPDU authInitRes = cardManager.transmit(authInitCmd);
        Assertions.assertEquals(0x9000, authInitRes.getSW(), "AUTH_INIT response status unexpected");
        byte[] cAuthInit = authInitRes.getData();
        Assertions.assertEquals(16, cAuthInit.length, "AUTH_INIT response has incorrect length");
        // Decrypt cAuthInit
        byte[] mAuthInit = aesDec(psk, cAuthInit);
        byte[] rc = Arrays.copyOfRange(mAuthInit, 0, 8);
        System.out.println("AUTH_INIT - rc: " + Util.bytesToHex(rc));
        byte[] mAuthInitSecondHalf = Arrays.copyOfRange(mAuthInit, 8, 16);
        byte[] mAuthInitExpectedSecondHalf = new byte[8];
        Assertions.assertArrayEquals(mAuthInitExpectedSecondHalf, mAuthInitSecondHalf,
                "Second half of decrypted AUTH_INIT response is not all 0");

        // ===== Step 2: AUTH =====
        byte[] rt = new byte[8];
        new Random(42).nextBytes(rt);
        System.out.println("AUTH - rt: " + Util.bytesToHex(rt));
        // Assemble plaintext for AUTH message and encrypt it
        byte[] mAuthCmd = new byte[16];
        System.arraycopy(rt, 0, mAuthCmd, 0, 8);
        System.arraycopy(rc, 0, mAuthCmd, 8, 8);
        byte[] cAuthCmd = aesEnc(psk, mAuthCmd);
        // Construct and send APDU
        CommandAPDU authCmd = new CommandAPDU(CLA_PROPRIETARY, INS_AUTH, 0x00, 0x00, cAuthCmd);
        ResponseAPDU authRes = cardManager.transmit(authCmd);
        Assertions.assertEquals(0x9000, authRes.getSW(), "AUTH response status unexpected");
        byte[] cAuthRes = authRes.getData();
        Assertions.assertEquals(16, cAuthRes.length, "AUTH response has incorrect length");
        // Derive ephemeral key
        byte[] ephKey = new byte[16];
        System.arraycopy(rc, 0, ephKey, 0, 8);
        System.arraycopy(rt, 0, ephKey, 8, 8);
        // Decrypt cAuthRes
        byte[] mAuthRes = aesDec(ephKey, cAuthRes);
        Assertions.assertArrayEquals(new byte[] {'A','U','T','H','_','S','U','C','C','E','S','S', 0, 0, 0, 0}, mAuthRes,
                "AUTH response plaintext is incorrect");

        // ===== Step 3: GET_ID =====
        CommandAPDU getIdCmd = new CommandAPDU(CLA_PROPRIETARY, INS_GET_ID, 0x00, 0x00);
        ResponseAPDU getIdRes = cardManager.transmit(getIdCmd);
        Assertions.assertEquals(0x9000, getIdRes.getSW(), "AUTH response status unexpected");
        byte[] cGetIdRes = getIdRes.getData();
        Assertions.assertEquals(16, cGetIdRes.length, "GET_ID response has incorrect length");
        // Decrypt cGetIdRes
        byte[] mGetIdRes = aesDec(ephKey, cGetIdRes);
        Assertions.assertArrayEquals(id, mGetIdRes, "GET_ID response is incorrect");

    }

    // ===== Helper functions =====
    private byte[] aesEnc(byte[] key, byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(plaintext);
    }

    private byte[] aesDec(byte[] key, byte[] ciphertext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(ciphertext);
    }
}
