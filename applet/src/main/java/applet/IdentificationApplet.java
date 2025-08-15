package applet;

import javacard.framework.*;

public class IdentificationApplet extends Applet
{

	// ===== APDU constants =====
	private static final byte CLA_PROPRIETARY = (byte) 0x80;
	private static final byte INS_GET_ID      = (byte) 0x12;

	// ===== Persistent data =====
	private final byte[] id = new byte[16]; 		// Card's identifier (ciphertext payload for GET_ID)

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new IdentificationApplet(bArray, bOffset, bLength);
	}

	public IdentificationApplet(byte[] params, short offset, byte length)
	{
		// The card ID needs to be set during applet installation
		if (length < 16) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}

		// Load ID (16 bytes)
		Util.arrayCopyNonAtomic(params, offset, id, (short) 0, (short) 16);

		register();
	}

	public void process(APDU apdu)
	{

		byte[] apduBuffer = apdu.getBuffer();
		byte cla = apduBuffer[ISO7816.OFFSET_CLA];
		byte ins = apduBuffer[ISO7816.OFFSET_INS];

		// Verify that class byte corresponds to "proprietary"
		if (cla != CLA_PROPRIETARY) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		// Handle all supported instructions
		switch (ins) {
			case INS_GET_ID:
				handleGetId(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void handleGetId(APDU apdu) {
		// Send response
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 16);
		apdu.sendBytesLong(id, (short) 0, (short) 16);
	}

}
