import com.WacomGSS.STU.ITabletHandler;
import com.WacomGSS.STU.Protocol.AsymmetricKeyType;
import com.WacomGSS.STU.Protocol.AsymmetricPaddingType;
import com.WacomGSS.STU.Protocol.Capability;
import com.WacomGSS.STU.Protocol.DHbase;
import com.WacomGSS.STU.Protocol.DHprime;
import com.WacomGSS.STU.Protocol.DevicePublicKey;
import com.WacomGSS.STU.Protocol.EncodingFlag;
import com.WacomGSS.STU.Protocol.EncodingMode;
import com.WacomGSS.STU.Protocol.EncryptionStatus;
import com.WacomGSS.STU.Protocol.EventDataKeyPad;
import com.WacomGSS.STU.Protocol.EventDataKeyPadEncrypted;
import com.WacomGSS.STU.Protocol.EventDataPinPad;
import com.WacomGSS.STU.Protocol.EventDataPinPadEncrypted;
import com.WacomGSS.STU.Protocol.EventDataSignature;
import com.WacomGSS.STU.Protocol.EventDataSignatureEncrypted;
import com.WacomGSS.STU.Protocol.Information;
import com.WacomGSS.STU.Protocol.InkingMode;
import com.WacomGSS.STU.Protocol.OperationMode;
import com.WacomGSS.STU.Protocol.OperationModeType;
import com.WacomGSS.STU.Protocol.OperationMode_Signature;
import com.WacomGSS.STU.Protocol.PenData;
import com.WacomGSS.STU.Protocol.PenDataEncrypted;
import com.WacomGSS.STU.Protocol.PenDataEncryptedOption;
import com.WacomGSS.STU.Protocol.PenDataOption;
import com.WacomGSS.STU.Protocol.PenDataTimeCountSequence;
import com.WacomGSS.STU.Protocol.PenDataTimeCountSequenceEncrypted;
import com.WacomGSS.STU.Protocol.ProtocolHelper;
import com.WacomGSS.STU.Protocol.PublicKey;
import com.WacomGSS.STU.Protocol.ReportId;
import com.WacomGSS.STU.Protocol.RomImageHash;
import com.WacomGSS.STU.Protocol.RomStartImageData;
import com.WacomGSS.STU.Protocol.SymmetricKeyType;
import com.WacomGSS.STU.STUException;
import com.WacomGSS.STU.Tablet;
import com.WacomGSS.STU.TlsDevice;
import com.WacomGSS.STU.UsbDevice;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Line2D;
import java.awt.geom.Point2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.math.BigInteger;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LekonSignature extends JFrame {
    private JPanel image;

    static class SignatureDialog extends JDialog implements ITabletHandler {

        static class MyEncryptionHandler implements Tablet.IEncryptionHandler {
            private BigInteger p;
            private BigInteger g;
            private BigInteger privateKey;
            private Cipher aesCipher;

            @Override
            public void reset() {
                clearKeys();
                this.p = null;
                this.g = null;
            }

            @Override
            public void clearKeys() {
                this.privateKey = null;
                this.aesCipher = null;
            }

            @Override
            public boolean requireDH() {
                return this.p == null || this.g == null;
            }

            @Override
            public void setDH(DHprime dhPrime, DHbase dhBase) {
                this.p = new BigInteger(1, dhPrime.getValue());
                this.g = new BigInteger(1, dhBase.getValue());
            }

            @Override
            public PublicKey generateHostPublicKey() {
                this.privateKey = new BigInteger("0F965BC2C949B91938787D5973C94856C", 16); // should be randomly chosen according to DH rules.

                BigInteger publicKey_bi = this.g.modPow(this.privateKey, this.p);
                try {
                    PublicKey publicKey = new PublicKey(publicKey_bi.toByteArray());
                    return publicKey;
                } catch (Exception e) {
                }
                return null;
            }

            @Override
            public void computeSharedKey(PublicKey devicePublicKey) {
                BigInteger devicePublicKey_bi = new BigInteger(1, devicePublicKey.getValue());
                BigInteger sharedKey = devicePublicKey_bi.modPow(this.privateKey, this.p);

                byte[] array = sharedKey.toByteArray();
                if (array[0] == 0) {
                    byte[] tmp = new byte[array.length - 1];
                    System.arraycopy(array, 1, tmp, 0, tmp.length);
                    array = tmp;
                }

                try {
                    Key aesKey = new SecretKeySpec(array, "AES");

                    this.aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
                    aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
                    return;
                } catch (Exception e) {
                }
                this.aesCipher = null;
            }

            @Override
            public byte[] decrypt(byte[] data) {
                try {
                    byte[] decryptedData = this.aesCipher.doFinal(data);
                    return decryptedData;
                } catch (Exception e) {
                }
                return null;
            }
        }


        static class MyEncryptionHandler2 implements Tablet.IEncryptionHandler2 {
            private BigInteger n;
            private BigInteger d;
            private BigInteger e;
            private Cipher aesCipher;

            public MyEncryptionHandler2() {
                this.e = BigInteger.valueOf(65537);
            }

            @Override
            public void reset() {
                clearKeys();
                this.d = null;
                this.n = null;
            }

            public void clearKeys() {
                this.aesCipher = null;
            }

            @Override
            public SymmetricKeyType getSymmetricKeyType() {
                return SymmetricKeyType.AES128;
                //return SymmetricKeyType.AES256; // requires "Java Crypotography Extension (JCE) Unlimited Strength Jurisdiction Policy Files"
            }

            @Override
            public AsymmetricPaddingType getAsymmetricPaddingType() {
                return AsymmetricPaddingType.None; // not recommended
                //return AsymmetricPaddingType.OAEP;
            }

            @Override
            public AsymmetricKeyType getAsymmetricKeyType() {
                return AsymmetricKeyType.RSA2048;
            }

            public String toHex(byte[] arr) {
                StringBuilder sb = new StringBuilder(arr.length * 2);
                java.util.Formatter formatter = new java.util.Formatter(sb);
                for (byte b : arr) {
                    formatter.format("%02x", b);
                }
                return sb.toString();
            }


            @Override
            public byte[] getPublicExponent() {
                byte[] ea = this.e.toByteArray();

                return ea;
            }

            @Override
            public byte[] generatePublicKey() {
                if (this.n != null) {
                    return n.toByteArray();
                }

                // Generate your key pair here.
                // For speed and ease of demonstration, we use some precalulated values.
                // This is NOT recommended for production use!

                this.n = new BigInteger("93DDCD8BC9E478491C54413F0484FE79DDDA464A0F53AC043C6194FD473FB75B893C783F56701D2D30B021C4EE0401F058B98F035804CFBB0E67A8136A2F052A98037457460FAB7B3B148EC7C95604FF2192EA03FCC04285EC539DDF3375678E4C4D926163ABBC609C41EF5673C449DF5AC74FFA8150D33FC5436C5CC2621E642C42C10E71BF3895B07A52E7D86C84D3A9269462CF2E484E17D34DEDFF9090D6745A00EF40EE33C71C5688E856AF3C6C42AF3C4C8523711498F4508DC18BC5E24F38C2C7E971BA61BB24B19E3AE74D4D57023AF59BA9D979FCF48080E18D920E31A319C544DEA0E9DAF088E09B6098C07C20328DD0F62C5C99FCD2EB7C4F7CD3", 16);
                this.d = new BigInteger("2B1DD41FDCE1180A098EAFEFD63B8990B3964044BC2F63CB6067FBEFD6E4C76C9399E45E63B01171E9EE920A40753EB37CCBAEDE04BE726C5308FAC39E84D376D618BBC5EF1206A8CA537646DF788BC07163CB851A205DC57B61EE78F52258EDEF65F7371ABF2B10E8BF7930B655184D5EC51B972A3A0D3F5D2009EB0A6B5DFCD8DDD29CA704CDFF2086A211CFE7E0C395E9B53D5B1FF370BFC90C3A8255A64A8674E8FB41002838ABFC430EA558DECFFE1B563D96D06DCAEA8A5793DCA68C3FB4265BCE38CBEFBBAEB3B8FC1689F7B8510BF20B9D72E490887FB36F4722FEB813E6252DDC3BB17DA645ACEE8292AB85FA1A3048B7BBB34F3B50489BE7913421", 16);

                return n.toByteArray();
            }

            @Override
            public void computeSessionKey(byte[] data) {
                BigInteger c = new BigInteger(1, data);

                BigInteger m = c.modPow(this.d, this.n);

                int keySizeBytes = 128 / 8;

                byte[] k = m.toByteArray();
                if (k.length != keySizeBytes) {
                    byte[] k2 = new byte[keySizeBytes];
                    System.arraycopy(k, k.length > keySizeBytes ? k.length - keySizeBytes : 0, k2, 0, k2.length);
                    k = k2;
                }

                Key aesKey = new SecretKeySpec(k, "AES");

                try {
                    this.aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
                    this.aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
                    return;
                } catch (Exception e) {
                }
                this.aesCipher = null;
            }

            @Override
            public byte[] decrypt(byte[] data) {
                try {
                    byte[] decryptedData = this.aesCipher.doFinal(data);
                    return decryptedData;
                } catch (Exception e) {
                }
                return null;
            }
        }


        private Tablet tablet;
        private Capability capability;
        private Information information;

        // In order to simulate buttons, we have our own Button class that stores the bounds and event handler.
        // Using an array of these makes it easy to add or remove buttons as desired.
        private static class Button {
            java.awt.Rectangle bounds;  // in Screen coordinates
            String text;
            ActionListener click;

            void performClick() {
                click.actionPerformed(null);
            }
        }

        // The isDown flag is used like this:
        // 0 = up
        // +ve = down, pressed on button number
        // -1 = down, inking
        // -2 = down, ignoring
        private int isDown;

        private List<PenData> penData; // Array of data being stored. This can be subsequently used as desired.

        private Button[] btns; // The array of buttons that we are emulating.

        private JPanel panel;

        private boolean useSigMode;   // use Signature Mode (STU-540 only)
        private BufferedImage bitmap; // This bitmap that we display on the screen.
        private EncodingMode encodingMode;  // How we send the bitmap to the device.
        private byte[] bitmapData;    // This is the flattened data of the bitmap that we send to the device.

        private boolean encrypted = false;


        private Point2D.Float tabletToClient(PenData penData) {
            // Client means the panel coordinates.
            return new Point2D.Float((float) penData.getX() * this.panel.getWidth() / this.capability.getTabletMaxX(),
                    (float) penData.getY() * this.panel.getHeight() / this.capability.getTabletMaxY());
        }


        private Point2D.Float tabletToScreen(PenData penData) {
            // Screen means LCD screen of the tablet.
            return new Point2D.Float((float) penData.getX() * this.capability.getScreenWidth() / this.capability.getTabletMaxX(),
                    (float) penData.getY() * this.capability.getScreenHeight() / this.capability.getTabletMaxY());
        }


        private Point clientToScreen(Point pt) {
            // client (window) coordinates to LCD screen coordinates.
            // This is needed for converting mouse coordinates into LCD bitmap coordinates as that's
            // what this application uses as the coordinate space for buttons.
            return new Point(Math.round((float) pt.getX() * this.capability.getScreenWidth() / this.panel.getWidth()),
                    Math.round((float) pt.getY() * this.capability.getScreenHeight() / this.panel.getHeight()));
        }


        private void pressOkButton() throws STUException {
            this.setVisible(false);
        }


        private void pressClearButton() throws STUException {
            clearScreen();
        }


        private void pressCancelButton() throws STUException {
            this.setVisible(false);
            this.penData = null;
        }


        private void clearScreen() throws STUException {
            if (!this.useSigMode) {
                this.tablet.writeImage(this.encodingMode, this.bitmapData);
            }
            this.penData.clear();
            this.isDown = 0;
            this.panel.repaint();
        }


        public void dispose() {
            // Ensure that you correctly disconnect from the tablet, otherwise you are
            // likely to get errors when wanting to connect a second time.
            if (this.tablet != null) {
                try {
                    this.tablet.setInkingMode(InkingMode.Off);

                    if (encrypted) {
                        this.tablet.endCapture();
                        encrypted = false;
                    }

                    this.tablet.setOperationMode(OperationMode.initializeNormal());
                    this.tablet.setClearScreen();
                } catch (Throwable t) {
                }
                this.tablet.disconnect();
                this.tablet = null;
            }

            super.dispose();
        }


        private void drawCenteredString(Graphics2D gfx, String text, int x, int y, int width, int height) {
            FontMetrics fm = gfx.getFontMetrics(gfx.getFont());
            int textHeight = fm.getHeight();
            int textWidth = fm.stringWidth(text);

            int textX = x + (width - textWidth) / 2;
            int textY = y + (height - textHeight) / 2 + fm.getAscent();

            gfx.drawString(text, textX, textY);
        }


        private void drawInk(Graphics2D gfx, PenData pd0, PenData pd1) {
            gfx.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            gfx.setColor(new Color(0, 0, 64, 255));
            gfx.setStroke(new BasicStroke(3, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));

            Point2D.Float pt0 = tabletToClient(pd0);
            Point2D.Float pt1 = tabletToClient(pd1);
            Shape l = new Line2D.Float(pt0, pt1);
            gfx.draw(l);
        }


        private void drawInk(Graphics2D gfx) {
            PenData[] pd = new PenData[0];
            pd = this.penData.toArray(pd);
            for (int i = 1; i < pd.length; ++i) {
                if (pd[i - 1].getSw() != 0 && pd[i].getSw() != 0) {
                    drawInk(gfx, pd[i - 1], pd[i]);
                }
            }
        }


        // Pass in the device you want to connect to!
        public SignatureDialog(Frame frame, UsbDevice usbDevice, TlsDevice tlsDevice) throws STUException {
            super(frame, true);
            this.setLocation(new Point(0, 0));
            this.setLocationRelativeTo(frame);
            this.panel = new JPanel() {
                @Override
                public void paintComponent(Graphics gfx) {
                    super.paintComponent(gfx);
                    if (bitmap != null) {
                        Image rescaled = bitmap.getScaledInstance(panel.getWidth(), panel.getHeight(), Image.SCALE_SMOOTH);
                        gfx.drawImage(rescaled, 0, 0, null);
                        drawInk((Graphics2D) gfx);
                    }
                }
            };
            this.panel.addMouseListener(new MouseAdapter() {
                public void mouseClicked(MouseEvent e) {
                    Point pt = clientToScreen(e.getPoint());
                    for (Button btn : SignatureDialog.this.btns) {
                        if (btn.bounds.contains(pt)) {
                            btn.performClick();
                            break;
                        }
                    }
                }
            });


            this.penData = new ArrayList<PenData>();

            try {
                this.tablet = new Tablet();
                // A more sophisticated applications should cycle for a few times as the connection may only be
                // temporarily unavailable for a second or so.
                // For example, if a background process such as Wacom STU Display
                // is running, this periodically updates a slideshow of images to the device.

                this.tablet.setEncryptionHandler(new MyEncryptionHandler());
                this.tablet.setEncryptionHandler2(new MyEncryptionHandler2());

                int e;
                if (usbDevice != null)
                    e = tablet.usbConnect(usbDevice, true);
                else
                    e = tablet.tlsConnect(tlsDevice);
                if (e == 0) {
                    this.capability = tablet.getCapability();
                    this.information = tablet.getInformation();
                } else {
                    throw new RuntimeException("Failed to connect to USB tablet, error " + e);
                }

                if (useSigMode && !tablet.isSupported(ReportId.OperationMode)) {
                    JOptionPane.showMessageDialog(this,
                            this.information.getModelName() + " does not support Signature Mode operation, reverting to normal operation",
                            "Warning",
                            JOptionPane.WARNING_MESSAGE);
                    useSigMode = false;
                }
                this.useSigMode = useSigMode;

                // Set the size of the client window to be actual size,
                // based on the reported DPI of the monitor.

                int screenResolution = this.getToolkit().getScreenResolution();

                Dimension d = new Dimension(this.capability.getTabletMaxX() * screenResolution / 2540, this.capability.getTabletMaxY() * screenResolution / 2540);
                this.panel.setPreferredSize(d);
                this.setLayout(new BorderLayout());
                this.setResizable(false);
                this.add(this.panel);
                this.pack();

                this.btns = new Button[3];
                this.btns[0] = new Button();
                this.btns[1] = new Button();
                this.btns[2] = new Button();

                if (useSigMode) {
                    // LCD is 800x480; Button positions and sizes are fixed
                    btns[0].bounds = new java.awt.Rectangle(0, 431, 265, 48);
                    btns[1].bounds = new java.awt.Rectangle(266, 431, 265, 48);
                    btns[2].bounds = new java.awt.Rectangle(532, 431, 265, 48);
                } else if (this.tablet.getProductId() != UsbDevice.ProductId_300) {
                    // Place the buttons across the bottom of the screen.

                    int w2 = this.capability.getScreenWidth() / 3;
                    int w3 = this.capability.getScreenWidth() / 3;
                    int w1 = this.capability.getScreenWidth() - w2 - w3;
                    int y = this.capability.getScreenHeight() * 6 / 7;
                    int h = this.capability.getScreenHeight() - y;

                    btns[0].bounds = new java.awt.Rectangle(0, y, w1, h);
                    btns[1].bounds = new java.awt.Rectangle(w1, y, w2, h);
                    btns[2].bounds = new java.awt.Rectangle(w1 + w2, y, w3, h);
                } else {
                    // The STU-300 is very shallow, so it is better to utilise
                    // the buttons to the side of the display instead.

                    int x = this.capability.getScreenWidth() * 3 / 4;
                    int w = this.capability.getScreenWidth() - x;

                    int h2 = this.capability.getScreenHeight() / 3;
                    int h3 = this.capability.getScreenHeight() / 3;
                    int h1 = this.capability.getScreenHeight() - h2 - h3;

                    btns[0].bounds = new java.awt.Rectangle(x, 0, w, h1);
                    btns[1].bounds = new java.awt.Rectangle(x, h1, w, h2);
                    btns[2].bounds = new java.awt.Rectangle(x, h1 + h2, w, h3);
                }

                btns[0].text = "Очистить";
                btns[0].click = new ActionListener() {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            pressClearButton();
                        } catch (STUException e) {
                            // e
                        }
                    }
                };

                btns[1].text = "Отменить";
                btns[1].click = new ActionListener() {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            pressCancelButton();
                        } catch (STUException e) {
                            // e
                        }
                    }
                };

                btns[2].text = "Готово";
                btns[2].click = new ActionListener() {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            pressOkButton();
                        } catch (STUException e) {
                            // e
                        }
                    }
                };

                byte encodingFlag = ProtocolHelper.simulateEncodingFlag(this.tablet.getProductId(), this.capability.getEncodingFlag());

                if ((encodingFlag & EncodingFlag.EncodingFlag_24bit) != 0) {
                    this.encodingMode = this.tablet.supportsWrite() ? EncodingMode.EncodingMode_24bit_Bulk : EncodingMode.EncodingMode_24bit;
                } else if ((encodingFlag & EncodingFlag.EncodingFlag_16bit) != 0) {
                    this.encodingMode = this.tablet.supportsWrite() ? EncodingMode.EncodingMode_16bit_Bulk : EncodingMode.EncodingMode_16bit;
                } else {
                    this.encodingMode = EncodingMode.EncodingMode_1bit;
                }


                if (useSigMode && !initializeSigMode()) {
                    JOptionPane.showMessageDialog(this,
                            "Exception initializing Signature Mode, reverting to normal operation",
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                    useSigMode = false;
                }

                if (!useSigMode) {
                    Color btnColor = (this.encodingMode == EncodingMode.EncodingMode_1bit) ? Color.WHITE : Color.LIGHT_GRAY;
                    this.bitmap = createScreenImage(new Color[]{btnColor, btnColor, btnColor}, Color.BLACK, null);

                    // Now the bitmap has been created, it needs to be converted to device-native
                    // format.
                    this.bitmapData = ProtocolHelper.flatten(this.bitmap, this.bitmap.getWidth(), this.bitmap.getHeight(), encodingMode);
                }

                // If you wish to further optimize image transfer, you can compress the image using
                // the Zlib algorithm.
                boolean useZlibCompression = false;

                if (this.encodingMode == EncodingMode.EncodingMode_1bit && useZlibCompression) {
                    // m_bitmapData = compress_using_zlib(m_bitmapData); // insert compression here!
                    // m_encodingMode = EncodingMode.EncodingMode_1bit_Zlib;
                }

                // Add the delagate that receives pen data.
                this.tablet.addTabletHandler(this);

                // Initialize the screen
                clearScreen();

                if (ProtocolHelper.supportsEncryption(tablet.getProtocol())) {
                    this.tablet.startCapture(0xc0ffee);
                    encrypted = true;
                }

                // Enable the pen data on the screen (if not already)
                this.tablet.setInkingMode(InkingMode.On);
            } catch (Throwable t) {
                if (this.tablet != null) {
                    this.tablet.disconnect();
                    this.tablet = null;
                }
                throw t;
            }
        }


        public void onGetReportException(STUException e) {
            JOptionPane.showMessageDialog(this, "Error:" + e, "Error (onGetReportException)", JOptionPane.ERROR_MESSAGE);
            this.tablet.disconnect();
            this.tablet = null;
            this.penData = null;
            this.setVisible(false);
        }


        public void onUnhandledReportData(byte[] data) {
        }


        public void onPenData(PenData penData) {
            Point2D pt = tabletToScreen(penData);

            int btn = 0; // will be +ve if the pen is over a button.
            {
                for (int i = 0; i < this.btns.length; ++i) {
                    if (this.btns[i].bounds.contains(pt)) {
                        btn = i + 1;
                        break;
                    }
                }
            }

            boolean isDown = (penData.getSw() != 0);

            // This code uses a model of four states the pen can be in:
            // down or up, and whether this is the first sample of that state.

            if (isDown) {
                if (this.isDown == 0) {
                    // transition to down
                    if (btn > 0) {
                        // We have put the pen down on a button.
                        // Track the pen without inking on the client.

                        this.isDown = btn;
                    } else {
                        // We have put the pen down somewhere else.
                        // Treat it as part of the signature.

                        this.isDown = -1;
                    }
                } else {
                    // already down, keep doing what we're doing!
                    // draw
                    if (!this.penData.isEmpty() && this.isDown == -1) {
                        // Draw a line from the previous down point to this down point.
                        // This is the simplist thing you can do; a more sophisticated program
                        // can perform higher quality rendering than this!
                        Graphics2D gfx = (Graphics2D) this.panel.getGraphics();
                        drawInk(gfx, this.penData.get(this.penData.size() - 1), penData);
                        gfx.dispose();
                    }

                }

                // The pen is down, store it for use later.
                if (this.isDown == -1)
                    this.penData.add(penData);
            } else {
                if (this.isDown != 0) {
                    // transition to up
                    if (btn > 0) {
                        // The pen is over a button

                        if (btn == this.isDown && !this.useSigMode) {
                            // The pen was pressed down over the same button as is was lifted now.
                            // Consider that as a click.
                            // In Signature Mode, click detection is handled by the tablet and
                            // generates a EventDataSignature/EventDataSignatureEncrypted event
                            this.btns[btn - 1].performClick();
                        }
                    }
                    this.isDown = 0;
                } else {
                    // still up
                }

                // Add up data once we have collected some down data.
                if (!this.penData.isEmpty())
                    this.penData.add(penData);
            }

        }


        public void onPenDataOption(PenDataOption penDataOption) {
            onPenData(penDataOption);
        }


        public void onPenDataEncrypted(PenDataEncrypted penDataEncrypted) {
            onPenData(penDataEncrypted.getPenData1());
            onPenData(penDataEncrypted.getPenData2());
        }


        public void onPenDataEncryptedOption(PenDataEncryptedOption penDataEncryptedOption) {
            onPenData(penDataEncryptedOption.getPenDataOption1());
            onPenData(penDataEncryptedOption.getPenDataOption2());
        }


        public void onPenDataTimeCountSequence(PenDataTimeCountSequence penDataTimeCountSequence) {
            onPenData(penDataTimeCountSequence);
        }


        public void onPenDataTimeCountSequenceEncrypted(PenDataTimeCountSequenceEncrypted penDataTimeCountSequenceEncrypted) {
            onPenData(penDataTimeCountSequenceEncrypted);
        }


        public void onEncryptionStatus(EncryptionStatus encryptionStatus) {
        }

        public void onDevicePublicKey(DevicePublicKey devicePublicKey) {
        }


        public void onEventDataPinPad(EventDataPinPad eventData) {
        }


        public void onEventDataKeyPad(EventDataKeyPad eventData) {
        }


        public void onEventDataSignature(EventDataSignature eventData) {
            onSignatureEvent(eventData.getKeyValue());
        }


        public void onEventDataPinPadEncrypted(EventDataPinPadEncrypted eventData) {
        }


        public void onEventDataKeyPadEncrypted(EventDataKeyPadEncrypted eventData) {
        }


        public void onEventDataSignatureEncrypted(EventDataSignatureEncrypted eventData) {
            onSignatureEvent(eventData.getKeyValue());
        }


        private void onSignatureEvent(byte keyValue) {
            try {
                switch (keyValue) {
                    case (byte) 0:
                        pressCancelButton();
                        break;

                    case (byte) 1:
                        pressOkButton();
                        break;

                    case (byte) 2:
                        pressClearButton();
                        break;
                }
            } catch (Exception ex) {
            }
        }


        public PenData[] getPenData() {
            if (this.penData != null) {
                PenData[] arrayPenData = new PenData[0];
                return this.penData.toArray(arrayPenData);
            }
            return null;
        }

        public Information getInformation() {
            if (this.penData != null) {
                return this.information;
            }
            return null;
        }


        public Capability getCapability() {
            if (this.penData != null) {
                return this.capability;
            }
            return null;
        }

        private static final byte sigScreenImageNum = (byte) 2;

        // Check if a Signature Mode screen image is already stored on the tablet. Download it if not.
        private void checkSigModeImage(boolean pushed, byte[] imageData) throws STUException, java.security.NoSuchAlgorithmException {
            boolean sigKeyEnabled[] = {true, true, true};
            RomStartImageData romStartImageData = RomStartImageData.initializeSignature(this.encodingMode, pushed, sigScreenImageNum, sigKeyEnabled);

            this.tablet.setRomImageHash(OperationModeType.Signature, pushed, sigScreenImageNum);

            RomImageHash romImgHash = tablet.getRomImageHash();

            boolean writeImage = true;
            if (romImgHash.getResult() == 0) {
                // There is already an image stored on the tablet corresponding to this image number and pushed state:
                // compare image hashes to determine if we need to overwrite it.
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
                byte[] hash = md.digest(imageData);
                if (Arrays.equals(hash, romImgHash.getHash())) {
                    // Image hashes match: no need to write image again
                    writeImage = false;
                }
            }
            // else - no image on pad, writeImage = true;

            if (writeImage) {
                tablet.writeRomImage(romStartImageData, imageData);
            }
        }

        // Create bitmap image for the tablet LCD screen and/or client (window).
        // This application uses the same size bitmap for both the screen and client.
        // However, at high DPI, this bitmap will be stretch and it would be better to
        // create individual bitmaps for screen and client at native resolutions.
        private BufferedImage createScreenImage(Color[] btnColors, Color txtColor, byte[] btnOrder) {
            BufferedImage image = new BufferedImage(this.capability.getScreenWidth(), this.capability.getScreenHeight(), BufferedImage.TYPE_INT_RGB);
            Graphics2D gfx = image.createGraphics();

            gfx.setColor(Color.WHITE);
            gfx.fillRect(0, 0, image.getWidth(), image.getHeight());

            double fontSize = (this.btns[0].bounds.getHeight() / 2.0); // pixels
            gfx.setFont(new Font("Arial", Font.PLAIN, (int) fontSize));

            // Draw the buttons
            for (int i = 0; i < this.btns.length; ++i) {
                // Button objects are created in the order, left-to-right, Clear / Cancel / OK
                // If reordering for Signature Mode (btnOrder != null), use bounds of another button when drawing
                // for image to be sent to tablet.
                Button btn = this.btns[i];
                java.awt.Rectangle bounds = this.btns[(btnOrder == null) ? i : btnOrder[i]].bounds;

                if (this.encodingMode != EncodingMode.EncodingMode_1bit) {
                    gfx.setColor(btnColors[i]);
                    gfx.fillRect((int) bounds.getX(), (int) bounds.getY(), (int) bounds.getWidth(), (int) bounds.getHeight());
                }
                gfx.setColor(txtColor);
                gfx.drawRect((int) bounds.getX(), (int) bounds.getY(), (int) bounds.getWidth(), (int) bounds.getHeight());
                drawCenteredString(gfx, btn.text, (int) bounds.getX(), (int) bounds.getY(), (int) bounds.getWidth(), (int) bounds.getHeight());
            }

            gfx.dispose();

            return image;
        }

        // Initialize Signature Mode (STU-540 only)
        private boolean initializeSigMode() {
            try {
                // Buttons on bitmaps sent to the tablet must be in the order Cancel / OK / Clear. The tablet will then
                // reorder button images displayed according to parameters passed to it in OperationMode_Signature
                // This application uses Clear / Cancel / OK
                byte[] btnOrder = {(byte) 2, (byte) 0, (byte) 1};
                Color[] btnsUpColors = new Color[]{new Color(0, 96, 255), Color.RED, Color.GREEN.darker()};
                Color[] btnsDownColors = new Color[]{btnsUpColors[0].darker(), btnsUpColors[1].darker(), btnsUpColors[2].darker()};
                byte[] bitmapData;

                BufferedImage btnsUp = createScreenImage(btnsUpColors, Color.BLACK, btnOrder);
                bitmapData = ProtocolHelper.flatten(btnsUp, btnsUp.getWidth(), btnsUp.getHeight(), encodingMode);
                checkSigModeImage(false, bitmapData);


                BufferedImage btnsPushed = createScreenImage(btnsDownColors, Color.WHITE, btnOrder);
                bitmapData = ProtocolHelper.flatten(btnsPushed, btnsPushed.getWidth(), btnsPushed.getHeight(), encodingMode);
                checkSigModeImage(true, bitmapData);

                OperationMode_Signature sigMode = new OperationMode_Signature(sigScreenImageNum, btnOrder, (byte) 0, (byte) 0);

                this.tablet.setOperationMode(OperationMode.initializeSignature(sigMode));

                this.bitmap = createScreenImage(btnsUpColors, Color.BLACK, null);

                return true;
            } catch (Exception ex) {
                return false;
            }
        }

    }

    String signatureFilename;
    BufferedImage signatureImage;
//    private JCheckBox chkUseSigMode;

    private Point2D.Float tabletToClient(PenData penData, Capability capability, JPanel panel) {
        // Client means the panel coordinates.
        //return new Point2D.Float( (float)penData.getX() * this.panel.getWidth()  / this.capability.getTabletMaxX(),
        //(float)penData.getY() * this.panel.getHeight() / this.capability.getTabletMaxY() );


        //System.out.println("tabletToClient X/Y " + penData.getX() + " " + penData.getY());
	   /*
	  System.out.println("Arg 1: " + penData.getX() * panel.getWidth() / capability.getTabletMaxX() );
	  System.out.println("Arg 2: " + penData.getY() * panel.getHeight() / capability.getTabletMaxY() );
	  */
        return new Point2D.Float((float) penData.getX() * panel.getWidth() / capability.getTabletMaxX(),
                (float) penData.getY() * panel.getHeight() / capability.getTabletMaxY());
    }

    private BufferedImage createImage(PenData[] penData, Capability capability, Information information) {
        BufferedImage bi = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D g = (Graphics2D) bi.getGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, bi.getWidth(), bi.getHeight());
        g.setColor(new Color(0, 0, 64, 255));
        g.setStroke(new BasicStroke(3, BasicStroke.CAP_ROUND,
                BasicStroke.JOIN_ROUND));
		
		/*
		System.out.println("Screen width/height: " + capability.getScreenWidth() + " " + capability.getScreenHeight());
		
		System.out.println("Converting pendata into graphics");
		System.out.println("Pendata length: " + penData.length);	
		System.out.println("image width + height: " + image.getWidth() + " " + image.getHeight());
	    System.out.println("Tabletmaxx " + capability.getTabletMaxX());
	    System.out.println("TabletmaxY " + capability.getTabletMaxY());
		*/
        for (int i = 1; i < penData.length; i++) {
            PenData p1 = penData[i];
            if (p1.getSw() != 0) {
                //System.out.println("Drawing point " + i);
                Point2D.Float pt1 = tabletToClient(penData[i - 1], capability, image);
                Point2D.Float pt2 = tabletToClient(penData[i], capability, image);
                //System.out.println("Creating shape");
                Shape l = new Line2D.Float(pt1, pt2);
                g.draw(l);
            }
        }
        //System.out.println("End of createImage");
        return bi;
    }


    private void onGetSignature() {
        try {
            com.WacomGSS.STU.UsbDevice[] usbDevices = UsbDevice.getUsbDevices();
            com.WacomGSS.STU.TlsDevice[] tlsDevices = TlsDevice.getTlsDevices();

            com.WacomGSS.STU.UsbDevice usbDevice = null;
            com.WacomGSS.STU.TlsDevice tlsDevice = null;
            if (usbDevices != null && usbDevices.length > 0)
                usbDevice = usbDevices[0];
            if (tlsDevices != null && tlsDevices.length > 0)
                tlsDevice = tlsDevices[0];

            if (usbDevice != null || tlsDevice != null) {
//                boolean sigMode = chkUseSigMode.isSelected();

                SignatureDialog signatureDialog = new SignatureDialog(this, usbDevice, tlsDevice);

                signatureDialog.setVisible(true);

                PenData[] penData = signatureDialog.getPenData();
                if (penData != null && penData.length > 0) {
                    // collected data!
                    this.signatureImage = createImage(penData, signatureDialog.getCapability(), signatureDialog.getInformation());
                    //System.out.println("Repainting");
                    image.repaint();
                    try {
                        ImageIO.write(this.signatureImage, "png", new File(this.signatureFilename));
                    } catch (Exception e) {
                    }
                }
                signatureDialog.dispose();

            } else {
                throw new RuntimeException("No tablets attached");
            }
        } catch (STUException e) {
            JOptionPane.showMessageDialog(this,
                    e,
                    "Error (STU)",
                    JOptionPane.ERROR_MESSAGE);
        } catch (RuntimeException e) {
            JOptionPane.showMessageDialog(this,
                    e,
                    "Error (RT)",
                    JOptionPane.ERROR_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    e,
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }


    public LekonSignature() {
        this.setTitle("Lekon Signature");
        this.setLayout(new BorderLayout());
        this.setMinimumSize(new Dimension(350, 100));
        this.setLocationRelativeTo(null);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.LINE_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        JButton btnGetSignature = new JButton("Получить подпись");
        btnGetSignature.setAlignmentX(CENTER_ALIGNMENT);
        btnGetSignature.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                onGetSignature();
            }
        });
        panel.add(btnGetSignature);

        JSeparator separator = new JToolBar.Separator(new Dimension(110, 0));
        panel.add(separator);

        JButton btnDone = new JButton("Готово");
        btnDone.setAlignmentX(CENTER_ALIGNMENT);
        btnDone.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                dispose();
            }
        });
        panel.add(btnDone);

        panel.add(Box.createRigidArea(new Dimension(0, 6)));

        image = new JPanel() {
            @Override
            public void paintComponent(Graphics gfx) {
                super.paintComponent(gfx);
                if (signatureImage != null) {
                    double newHeight = ((double) signatureImage.getHeight() / signatureImage.getWidth()) * this.getWidth();
                    Image rescaled = signatureImage.getScaledInstance(this.getWidth(), (int) newHeight, Image.SCALE_AREA_AVERAGING);
                    gfx.drawImage(rescaled, 0, (int) ((this.getHeight() / 2) - (newHeight / 2)), null);
                }
            }
        };
        image.setPreferredSize(new Dimension(300, 100));


        this.add(panel, BorderLayout.NORTH);
        this.add(image, BorderLayout.SOUTH);
        this.pack();
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }


    private static void runProgram(String signatureFilename) {
        LekonSignature sample = new LekonSignature();
        sample.setVisible(true);
        sample.signatureFilename = signatureFilename;
    }


    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                runProgram(args[0]);
            }
        });
    }
}
