package applet;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class MainApplet extends Applet
{

	// ===== APDU constants =====
	private static final byte CLA_PROPRIETARY = (byte) 0x80;
	private static final byte INS_AUTH_INIT   = (byte) 0x10;
	private static final byte INS_AUTH        = (byte) 0x11;
	private static final byte INS_GET_ID      = (byte) 0x12;

	// ===== Keys & crypto =====
	private final AESKey preSharedKey;              // Pre-shared long-term AES-128 key
	private final AESKey ephemeralKey;              // Ephemeral AES-128 (rc || rt')
	private final Cipher aesEcb;      				// AES/ECB/NOPAD for both keys
	private final RandomData rng;

	// ===== Persistent data =====
	private final byte[] id = new byte[16]; 		// Card's identifier (ciphertext payload for GET_ID)

	// ===== Session state =====
	private final byte[] rc = new byte[8];       	// Card nonce (64-bit)
	private final byte[] rt = new byte[8];       	// Decrypted terminal nonce (64-bit)
	private final byte[] cipherIn = new byte[16];   // AES input
	private final byte[] cipherOut = new byte[16];  // AES output
	private final byte[] tmpBuffer = new byte[16];  // Temporary scratch buffer used for ephemeral key construction
	private boolean ephemeralKeyReady = false;      // Has AUTH set the ephemeral key?
	private boolean authSuccess = false;         	// Does rc' match rc?

	// ===== 16-byte status messages returned after AUTH =====
	private final byte[] MSG_SUCCESS = {'A','U','T','H','_','S','U','C','C','E','S','S', 0, 0, 0, 0};;
	private final byte[] MSG_FAILURE = {'A','U','T','H','_','F','A','I','L','U','R','E', 0, 0, 0, 0};;

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new MainApplet(bArray, bOffset, bLength);
	}
	
	public MainApplet(byte[] params, short offset, byte length)
	{
		// The pre-shared key and the card ID need to be set during applet installation
		if (length < 32) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}

		// Build keys / cipher objects
		preSharedKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		ephemeralKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		aesEcb = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		rng = RandomData.getInstance(RandomData.ALG_TRNG);

		// Load pre-shared key (first 16 bytes)
		preSharedKey.setKey(params, offset);

		// Load ID (next 16 bytes)
		Util.arrayCopyNonAtomic(params, (short) (offset + 16), id, (short) 0, (short) 16);

		register();
	}

	public void process(APDU apdu)
	{

		// Reset session on (re-)select
		if (selectingApplet()) {
			ephemeralKeyReady = false;
			authSuccess = false;
			Util.arrayFillNonAtomic(rc, (short) 0, (short) rc.length, (byte) 0);
			return;
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
			case INS_AUTH_INIT:
				handleAuthInit(apdu);
				break;
			case INS_AUTH:
				handleAuth(apdu);
				break;
			case INS_GET_ID:
				handleGetId(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void handleAuthInit(APDU apdu) {
		// Reset previous session state
		// => Relevant in case several subsequent authentication attempts occur within the same session
		ephemeralKeyReady = false;
		authSuccess = false;

		// Sample a new 64-bit random nonce
		rng.nextBytes(rc, (short) 0, (short) 8);

		// Construct plaintext block pt = rc || 0^64
		Util.arrayCopyNonAtomic(rc, (short) 0, cipherIn, (short) 0, (short) 8);
		Util.arrayFillNonAtomic(cipherIn, (short) 8, (short) 8, (byte) 0);

		// Encrypt under the pre-shared key
		aesEcb.init(preSharedKey, Cipher.MODE_ENCRYPT);
		aesEcb.doFinal(cipherIn, (short) 0, (short) 16, cipherOut, (short) 0);

		// Send response
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 16);
		apdu.sendBytesLong(cipherOut, (short) 0, (short) 16);
	}

	private void handleAuth(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();

		// Check that length of data corresponds to 16 bytes
		short lc = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xff);
		if (lc != 16) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Receive 16 bytes and store them into cipherIn
		short read = apdu.setIncomingAndReceive();
		short copied = 0;
		while (read > 0 && (copied + read) <= 16) {
			Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, cipherIn, copied, read);
			copied += read;
			read = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		}

		// Double-check that the correct amount of data was copied
		if (copied != 16) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Decrypt ciphertext with pre-shared key to get: m = rt || rc'
		aesEcb.init(preSharedKey, Cipher.MODE_DECRYPT);
		aesEcb.doFinal(cipherIn, (short) 0, (short) 16, cipherOut, (short) 0);

		// Copy recovered rt to an internal buffer
		Util.arrayCopyNonAtomic(cipherOut, (short) 0, rt, (short) 0, (short) 8);
		// Authentication is successful, if the recovered card nonce matches the originally chosen value rc
		authSuccess = equals(cipherOut, (short) 8, rc, (short) 0, (short) 8);

		// Derive ephemeral key: k_eph = rc || rt
		Util.arrayCopyNonAtomic(rc, (short) 0, tmpBuffer, (short) 0, (short) 8);
		Util.arrayCopyNonAtomic(rt, (short) 0, tmpBuffer, (short) 8, (short) 8);
		ephemeralKey.setKey(tmpBuffer, (short) 0);
		ephemeralKeyReady = true;

		// Encrypt the corresponding response message
		byte[] responseMessage = authSuccess ? MSG_SUCCESS : MSG_FAILURE;
		aesEcb.init(ephemeralKey, Cipher.MODE_ENCRYPT);
		aesEcb.doFinal(responseMessage, (short) 0, (short) 16, cipherOut, (short) 0);

		// Send response
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 16);
		apdu.sendBytesLong(cipherOut, (short) 0, (short) 16);
	}

	private void handleGetId(APDU apdu) {
		// Ensure that authentication was already performed
		if (!authSuccess || !ephemeralKeyReady) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		// Encrypt the identifier stored on the card
		aesEcb.init(ephemeralKey, Cipher.MODE_ENCRYPT);
		aesEcb.doFinal(id, (short) 0, (short) 16, cipherOut, (short) 0);

		// Send response
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) 16);
		apdu.sendBytesLong(cipherOut, (short) 0, (short) 16);
	}

	// ===== Helper functions =====
	private static boolean equals(byte[] a, short aOffset, byte[] b, short bOffset, short length) {
		short diff = 0;
		for (short i = 0; i < length; i++) {
			diff |= (short) ((a[(short) (aOffset + i)] ^ b[(short) (bOffset + i)]) & 0xff);
		}
		return diff == 0;
	}

}
