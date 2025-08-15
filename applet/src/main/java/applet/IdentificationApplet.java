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

	public IdentificationApplet(byte[] bArray, short bOffset, byte bLength) {
		// bArray starts with length of instance AID, followed by the instance AID itself
		short li = (short) bArray[bOffset];
		// Then: Length of control info, followed by control info
		short lc = (short) bArray[(short) ((bOffset + li + 1) & 0xff)];
		// Afterward: Length of applet data, followed by applet data itself
		short appletDataLength = (short) bArray[(short) ((bOffset + li + lc + 2) & 0xff)];
		short appletDataOffset = (short) ((bOffset + li + lc + 3) & 0xff);

		// The applet data needs to contain the 16-byte card ID
		if (appletDataLength < 16) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}

		// Load ID (16 bytes)
		Util.arrayCopyNonAtomic(bArray, appletDataOffset, id, (short) 0, (short) 16);

		// Register new applet instance
		register();
	}

	public void process(APDU apdu)
	{

		// Do nothing on (re-)select and just return a success message
		if (selectingApplet()) {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}

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
