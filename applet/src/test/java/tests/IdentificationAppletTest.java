package tests;

import applet.IdentificationApplet;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.Util;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Tests for the unauthenticated identification applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Niklas Höher
 */
public class IdentificationAppletTest extends BaseTest {

    // ===== Configuration options =====
    private final static CardType CARDTYPE = CardType.PHYSICAL; // or: CardType.JCARDSIMLOCAL

    private final static String APPLET_ID = "f000000cdc00";
    private final static String idHex = "00000000000000000000000000000001";

    // ===== APDU constants =====
    private static final byte CLA_PROPRIETARY = (byte) 0x80;
    private static final byte INS_GET_ID      = (byte) 0x12;

    public IdentificationAppletTest() {
        super(APPLET_ID, IdentificationApplet.class, CARDTYPE);
    }

    @Test
    public void testCorrectProtocolFlow() throws Exception {
        final byte[] id = Util.hexStringToByteArray(idHex);
        // Install data: AID length = 0, Control data length = 0, Applet data length = id.length
        final byte[] installData = Util.hexStringToByteArray("0000" + Integer.toHexString(id.length) + idHex);

        // Initialize connection to card / simulator
        final CardManager cardManager = connect(installData);

        CommandAPDU getIdCmd = new CommandAPDU(CLA_PROPRIETARY, INS_GET_ID, 0x00, 0x00);
        ResponseAPDU getIdRes = cardManager.transmit(getIdCmd);
        Assertions.assertEquals(0x9000, getIdRes.getSW(), "AUTH response status unexpected");
        byte[] mGetIdRes = getIdRes.getData();
        Assertions.assertEquals(16, mGetIdRes.length, "GET_ID response has incorrect length");
        Assertions.assertArrayEquals(id, mGetIdRes, "GET_ID response is incorrect");
    }
}
