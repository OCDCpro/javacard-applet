package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.RunConfig;
import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.Applet;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;

/**
 * Base Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda, Dusan Klinec (ph4r05), Niklas Höher
 */
public class BaseTest {
    // Configurable options
    private String APPLET_AID;
    private Class<? extends Applet> appletClass;
    private CardType cardType;

    // Other required fields
    private byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);
    private boolean simulateStateful;
    protected CardManager statefulCard = null;

    public BaseTest(String appletId, Class<? extends Applet> appletClass, CardType cardType) {
        this.APPLET_AID = appletId;
        this.appletClass = appletClass;
        this.cardType = cardType;
    }

    /**
     * Creates card manager and connects to the card.
     *
     * @return
     * @throws Exception
     */
    public CardManager connect() throws Exception {
        return connect(null);
    }

    public CardManager connect(byte[] installData) throws Exception {
        if (simulateStateful && statefulCard != null){
            return statefulCard;
        } else if (simulateStateful){
            statefulCard = connectRaw(installData);
            return statefulCard;
        }

        return connectRaw(installData);
    }

    public CardManager connectRaw(byte[] installData) throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        System.setProperty("com.licel.jcardsim.object_deletion_supported", "1");
        System.setProperty("com.licel.jcardsim.sign.dsasigner.computedhash", "1");
        System.setProperty("com.licel.jcardsim.randomdata.seed", "42");

        runCfg.setTestCardType(cardType);
        if (cardType == CardType.REMOTE){
            runCfg.setRemoteAddress("http://127.0.0.1:9901");

            runCfg.setRemoteCardType(CardType.PHYSICAL);
            // runCfg.setRemoteCardType(CardType.JCARDSIMLOCAL);

            runCfg.setAid(APPLET_AID_BYTE);  // performs select after connect

        } else if (cardType != CardType.PHYSICAL && cardType != CardType.PHYSICAL_JAVAX) {
            // Running in the simulator
            runCfg.setAppletToSimulate(appletClass)
                    .setTestCardType(CardType.JCARDSIMLOCAL)
                    .setbReuploadApplet(true)
                    .setInstallData(installData);
        }

        if (!cardMngr.connect(runCfg)) {
            throw new RuntimeException("Connection failed");
        }

        return cardMngr;
    }

    /**
     * Convenience method for connecting and sending
     * @param cmd
     * @return
     */
    public ResponseAPDU connectAndSend(CommandAPDU cmd) throws Exception {
        return connect().transmit(cmd);
    }

    /**
     * Convenience method for building APDU command
     * @param data
     * @return
     */
    public static CommandAPDU buildApdu(String data){
        return new CommandAPDU(Util.hexStringToByteArray(data));
    }

    /**
     * Convenience method for building APDU command
     * @param data
     * @return
     */
    public static CommandAPDU buildApdu(byte[] data){
        return new CommandAPDU(data);
    }

    /**
     * Convenience method for building APDU command
     * @param data
     * @return
     */
    public static CommandAPDU buildApdu(CommandAPDU data){
        return data;
    }

    /**
     * Sending command to the card.
     * Enables to send init commands before the main one.
     *
     * @param cardMngr
     * @param command
     * @param initCommands
     * @return
     * @throws CardException
     */
    public ResponseAPDU sendCommandWithInitSequence(CardManager cardMngr, String command, ArrayList<String> initCommands) throws CardException {
        if (initCommands != null) {
            for (String cmd : initCommands) {
                cardMngr.getChannel().transmit(buildApdu(cmd));
            }
        }

        final ResponseAPDU resp = cardMngr.getChannel().transmit(buildApdu(command));
        return resp;
    }

    public CardType getCardType() {
        return cardType;
    }

    public boolean isSimulateStateful() {
        return simulateStateful;
    }

    public void setSimulateStateful(boolean simulateStateful) {
        this.simulateStateful = simulateStateful;
    }

    public boolean isPhysical() {
        return cardType == CardType.PHYSICAL || cardType == CardType.PHYSICAL_JAVAX;
    }

    public boolean isStateful(){
        return isPhysical() || simulateStateful;
    }

    public boolean canReinstall(){
        return !isPhysical() && !simulateStateful;
    }
}
