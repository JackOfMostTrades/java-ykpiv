package com.github.jackofmosttrades.ykpiv;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This is the core class representing access to a yubikey's PIV application. Once constructed, a YkPiv object should
 * be cleaned up by calling close().
 */
public class YkPiv implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(YkPiv.class.getName());

    public static final ByteString DEFAULT_MGMT_KEY = ByteString.copyOf(new byte[] {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8});
    public static final String DEFAULT_PIN = "123456";
    public static final String DEFAULT_PUK = "12345678";

    private Card card;

    public YkPiv() throws YkPivException {
        this("YubiKey");
    }

    /**
     * Construct a YkPiv instance where we attempt to connect to a YubiKey with a name containing the wanted string.
     * Pass in null to connect to any smartcard device on the system.
     * @param wanted
     * @throws YkPivException
     */
    public YkPiv(String wanted) throws YkPivException {
        this.card = null;
        connect(wanted);
    }

    /**
     * Close the connection to the underlying yubikey and cleanup resources. No method calls are valid on this object
     * after calling close()
     * @throws YkPivException
     */
    @Override
    public void close() throws YkPivException {
        if (card != null) {
            try {
                card.disconnect(true);
            } catch (CardException e) {
                throw new YkPivException("Exception trying to close connection", e);
            }
            card = null;
        }
    }

    private void connect(String wanted) throws YkPivException {
        if (card != null) {
            throw new IllegalStateException("Already connected.");
        }

        final List<CardTerminal> terminals;
        try {
            terminals = TerminalFactory.getDefault().terminals().list();
        } catch (CardException e) {
            throw new YkPivException("Unable to get card readers.", e);
        }
        for (CardTerminal cardTerminal : terminals) {
            if (wanted != null) {
                if (!cardTerminal.getName().contains(wanted)) {
                    continue;
                }
            }
            Card card;
            try {
                card = cardTerminal.connect("T=1");
            } catch (CardException e) {
                LOGGER.log(Level.WARNING, "Failed to connect to reader.", e);
                continue;
            }

            // Now try to select the ykpiv application from this card
            try {
                ResponseAPDU response = card.getBasicChannel().transmit(
                        new CommandAPDU(0, 0xa4, 0x04, 0x00, InternalConstants.APPLICATION_ID));
                if (response.getSW() != InternalConstants.SW_SUCCESS) {
                    throw new YkPivException(String.format("Failed selecting application: %04x", response.getSW()));
                }
            } catch (CardException e) {
                LOGGER.log(Level.WARNING, "Failed communicating with card", e);
                continue;
            }

            this.card = card;
            return;
        }

        throw new YkPivException("no usable reader found.");
    }

    /**
     * Issues a login instruction to the yubikey. If pin is null, it will just return the number of attempts remaining.
     * If login was successful, this will return -1. Otherwise it will return the number of pin attempts remaining.
     * @param pin
     * @return
     * @throws YkPivException
     */
    private int loginInternal(String pin) throws YkPivException {
        byte[] pinBytes = null;
        if (pin != null) {
            pinBytes = pin.getBytes(StandardCharsets.UTF_8);
            if (pinBytes.length > 8) {
                throw new IllegalArgumentException("PIN cannot be longer than 8 bytes.");
            }
            if (pinBytes.length < 8) {
                byte[] extended = new byte[8];
                System.arraycopy(pinBytes, 0, extended, 0, pinBytes.length);
                for (int i = pinBytes.length; i < 8; i++) {
                    extended[i] = (byte) 0xff;
                }
                pinBytes = extended;
            }
        }

        ResponseAPDU response;
        try {
            response = card.getBasicChannel().transmit(
                    new CommandAPDU(0x00, InternalConstants.YKPIV_INS_VERIFY, 0x00, 0x80, pinBytes));
        } catch (CardException e) {
            throw new YkPivException("Error sending verify ADPU", e);
        }

        if (response.getSW() == InternalConstants.SW_SUCCESS) {
            return -1;
        }
        if ((response.getSW() >> 8) == 0x63) {
            return (response.getSW() & 0xf);
        }
        if (response.getSW() == InternalConstants.SW_ERR_AUTH_BLOCKED) {
            return 0;
        }
        throw new YkPivException("Unexpected SW result: " + response.getSW());
    }

    /**
     * Attempts to login and authenticate with the given pin. Returns true if successful and false otherwise. Note that
     * this may return false even with the correct pin if the PIN is blocked; see getNumPinAttemptsRemaining().
     * @param pin
     * @return true if logging in was successful
     * @throws YkPivException
     */
    public boolean login(String pin) throws YkPivException {
        int result = loginInternal(pin);
        if (result == -1) {
            return true;
        }
        return false;
    }

    /**
     * Gets the number of PIN attempts remaining. If this instance of YkPiv is already in a logged-in state, this
     * will return -1.
     * @return
     * @throws YkPivException
     */
    public int getNumPinAttemptsRemaining() throws YkPivException {
        return loginInternal(null);
    }

    private ByteString transferData(final CommandAPDU adpu, ByteString data) throws YkPivException {
        try {
            card.beginExclusive();
        } catch (CardException e) {
            throw new YkPivException("Unable to begin transaction.", e);
        }

        try {
            // Send all the data packets
            int sw;
            int index = 0;
            final int max_length = 0xff;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            do {
                // If we can't fit the rest into a single message
                CommandAPDU partialAdpu;
                int send_length;
                if (index + max_length < data.getLength()) {
                    send_length = max_length;
                    partialAdpu = new CommandAPDU(0x10, adpu.getINS(), adpu.getP1(), adpu.getP2(),
                            data.slice(index, send_length).toByteArray());
                } else {
                    send_length = data.getLength() - index;
                    partialAdpu = new CommandAPDU(adpu.getCLA(), adpu.getINS(), adpu.getP1(), adpu.getP2(),
                            data.slice(index, send_length).toByteArray());
                }

                ResponseAPDU response = card.getBasicChannel().transmit(partialAdpu);
                sw = response.getSW();
                if (sw != InternalConstants.SW_SUCCESS && (sw >> 8) != 0x61) {
                    throw new YkPivException(String.format("Error transmitting data: sw=%x", sw));
                }
                baos.write(response.getData());

                index += send_length;
            } while (index < data.getLength());

            // Now read all data back
            while (sw >> 8 == 0x61) {
                ResponseAPDU response = card.getBasicChannel().transmit(new CommandAPDU(0x00, 0xc0, 0x00, 0x00));
                sw = response.getSW();
                if (sw != InternalConstants.SW_SUCCESS && sw >> 8 != 0x61) {
                    throw new YkPivException(String.format("Error transmitting data: sw=%x", sw));
                }
                baos.write(response.getData());
            }

            return ByteString.copyOf(baos.toByteArray());
        } catch (CardException | IOException e) {
            throw new YkPivException("Unable to transmit data to card.", e);
        } finally {
            try {
                card.endExclusive();
            } catch (CardException e) {
                LOGGER.log(Level.WARNING, "Unable to end transaction", e);
            }
        }
    }

    /**
     * Authenticates to the card, using the 24-byte MGMT key.
     * @param mgmtKey
     */
    public void authenticate(ByteString mgmtKey) throws YkPivException {
        final byte[] keyBytes = mgmtKey.toByteArray();
        try {
            // get a challenge from the card
            ResponseAPDU response = card.getBasicChannel().transmit(
                    new CommandAPDU(0x00, InternalConstants.YKPIV_INS_AUTHENTICATE, InternalConstants.YKPIV_ALGO_3DES, InternalConstants.YKPIV_KEY_CARDMGM,
                            new byte[]{0x7c, 0x02, (byte) 0x80, 0x00}));
            if (response.getSW() != InternalConstants.SW_SUCCESS) {
                throw new YkPivException("Unable to get challenge from card.");
            }
            final byte[] challenge = new byte[8];
            System.arraycopy(response.getData(), 4, challenge, 0, challenge.length);

            // send a response to the cards challenge and a challenge of our own.
            Cipher decCipher = Cipher.getInstance("DESede/ECB/NoPadding");
            decCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"));
            final byte[] challengeResp = decCipher.doFinal(challenge);

            final byte[] ourChallange = new byte[8];
            new SecureRandom().nextBytes(ourChallange);

            // The message is 0x7c, 20, 0x80, 8, <challengeResp>, 0x81, 8, <ourChallenge>
            final byte[] data = new byte[22];
            data[0] = 0x7c;
            data[1] = 20; // Length of the rest of the data
            data[2] = (byte) 0x80;
            data[3] = 8;
            System.arraycopy(challengeResp, 0, data, 4, challengeResp.length);
            data[12] = (byte) 0x81;
            data[13] = 8;
            System.arraycopy(ourChallange, 0, data, 14, ourChallange.length);

            response = card.getBasicChannel().transmit(
                    new CommandAPDU(0x00, InternalConstants.YKPIV_INS_AUTHENTICATE, InternalConstants.YKPIV_ALGO_3DES, InternalConstants.YKPIV_KEY_CARDMGM, data));
            if (response.getSW() != InternalConstants.SW_SUCCESS) {
                throw new YkPivException("Authentication error responding to MGMT key challange. Is your MGMT key correct?");
            }

            // compare the response from the card with our challenge
            byte[] cardChallengeResp = new byte[8];
            System.arraycopy(response.getData(), 4, cardChallengeResp, 0, cardChallengeResp.length);

            // Use a constant-time equality check (just as a matter of good practice)
            Cipher encCipher = Cipher.getInstance("DESede/ECB/NoPadding");
            encCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"));
            if (!MessageDigest.isEqual(cardChallengeResp, encCipher.doFinal(ourChallange))) {
                throw new YkPivException("Failed to verify card challenge response.");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException("Unexpected exception performing crypto", e);
        } catch (CardException e) {
            throw new YkPivException("Unable to authenticate with management key.", e);
        }
    }

    /**
     * Sets a new management key
     * @param newKey
     * @throws YkPivException If you have not yet successfully called authenticate.
     */
    public void setMgmtKey(ByteString newKey) throws YkPivException {
        setMgmtKey(newKey, false);
    }

    /**
     * Sets a new management key
     * @param newKey
     * @param requireTouch Should the yubikey require user presence whenever authenticating.
     * @throws YkPivException If you have not yet successfully called authenticate.
     */
    public void setMgmtKey(ByteString newKey, boolean requireTouch) throws YkPivException {

        if (newKey.getLength() != 24) {
            throw new IllegalArgumentException("Management key must be exactly 24 bytes long.");
        }
        // FIXME: This skips weak key checking that's in the C ykpiv library
        final byte[] data = new byte[3+newKey.getLength()];
        data[0] = InternalConstants.YKPIV_ALGO_3DES;
        data[1] = InternalConstants.YKPIV_KEY_CARDMGM;
        data[2] = (byte)newKey.getLength();
        newKey.writeTo(0, data, 3, newKey.getLength());

        ResponseAPDU response;
        try {
            response = card.getBasicChannel().transmit(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_SET_MGMKEY, 0xff, requireTouch ? 0xfe : 0xff,
                    data));
        } catch (CardException e) {
            throw new YkPivException("Communication exception when changing the MGMT key.", e);
        }

        if (response.getSW() != InternalConstants.SW_SUCCESS) {
            throw new YkPivException("Received an error when changing the MGMT key. Make sure you authenticate first.");
        }
    }

    /**
     * Returns a string representing the version of the yubikey firmware.
     * @return
     * @throws YkPivException
     */
    public String getVersion() throws YkPivException {

        ResponseAPDU response = null;
        try {
            response = card.getBasicChannel().transmit(new CommandAPDU(
                    0x00, InternalConstants.YKPIV_INS_GET_VERSION, 0x00, 0x00));
        } catch (CardException e) {
            throw new YkPivException("Unable to communicate with card.", e);
        }
        if (response.getSW() != InternalConstants.SW_SUCCESS) {
            throw new YkPivException("Unable to get yubikey version.");
        }

        final byte[] data = response.getData();
        return String.format("%d.%d.%d", data[0], data[1], data[2]);
    }

    private ByteString generateAuthenticate(ByteString input, byte algorithm, byte key, boolean decipher) throws YkPivException {
        int key_len = 0;
        switch(algorithm) {
            case InternalConstants.YKPIV_ALGO_RSA1024:
                key_len = 128;
                // Falls through
            case InternalConstants.YKPIV_ALGO_RSA2048:
                if(key_len == 0) {
                    key_len = 256;
                }
                if(input.getLength() != key_len) {
                    throw new IllegalArgumentException("Input length does not match key length: " + input.getLength() + " != " + key_len);
                }
                break;
            case InternalConstants.YKPIV_ALGO_ECCP256:
                key_len = 32;
                // Falls through
            case InternalConstants.YKPIV_ALGO_ECCP384:
                if(key_len == 0) {
                    key_len = 48;
                }
                if(!decipher && input.getLength() > key_len) {
                    throw new IllegalArgumentException("Input length greater than key length: " + input.getLength() + " > " + key_len);
                } else if(decipher && input.getLength() != (key_len * 2) + 1) {
                    throw new IllegalArgumentException("Input length incorrect: " + input.getLength() + " != " + (key_len * 2 + 1));
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        final boolean isEcAlg = (algorithm == InternalConstants.YKPIV_ALGO_ECCP256 || algorithm == InternalConstants.YKPIV_ALGO_ECCP384);
        final ByteString data = SimpleAsn1.build((byte)0x7c,
                SimpleAsn1.build((byte)0x82, ByteString.EMPTY),
                SimpleAsn1.build(isEcAlg && decipher ? (byte)0x85 : (byte)0x81, input));

        ByteString output = transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_AUTHENTICATE, algorithm, key), data);
        SimpleAsn1.Asn1Object out = SimpleAsn1.decodeSingleton(output);
        if (out.getTag() != 0x7c) {
            throw new YkPivException("Failed parsing signature reply; got unexpected tag: " + out.getTag());
        }
        out = SimpleAsn1.decodeSingleton(out.getData());
        if (out.getTag() != 0x82) {
            throw new YkPivException("Failed parsing signature reply; got unexpected tag: " + out.getTag());
        }
        return out.getData();
    }

    /**
     * Performs a PKCS#1 v1.5 signature on data read from the inputStream, hashed with the given hash algorithm, signed using the provided key algorithm,
     * using the key from the given key slot.
     *
     * @param inputStream
     * @param hashAlg
     * @param algorithm
     * @param keySlot
     * @return
     * @throws YkPivException
     * @throws IOException
     */
    public ByteString hashAndSign(InputStream inputStream, Hash hashAlg, KeyAlgorithm algorithm, KeySlot keySlot) throws YkPivException, IOException {
        try {
            final byte[] buffer = new byte[4096];
            int n;
            MessageDigest md = MessageDigest.getInstance(hashAlg.getJceAlgorithmName());
            while ((n = inputStream.read(buffer)) > 0) {
                md.update(buffer, 0, n);
            }
            return sign(ByteString.copyOf(md.digest()), hashAlg, algorithm, keySlot);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Invalid hash algorithm: " + hashAlg);
        }
    }

    /**
     * Performs a PKCS#1 v1.5 signature on data provided by input, hashed with the given hash algorithm, signed using the provided key algorithm,
     * using the key from the given key slot.
     *
     * @param input
     * @param hashAlg
     * @param algorithm
     * @param keySlot
     * @return
     * @throws YkPivException
     * @throws IOException
     */
    public ByteString hashAndSign(byte[] input, Hash hashAlg, KeyAlgorithm algorithm, KeySlot keySlot) throws YkPivException {
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlg.getJceAlgorithmName());
            return sign(ByteString.copyOf(md.digest(input)), hashAlg, algorithm, keySlot);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Invalid hash algorithm: " + hashAlg);
        }
    }

    // https://golang.org/src/crypto/rsa/pkcs1v15.go#L204
    private static final Map<Hash, ByteString> SIG_HASH_PREFIX;
    static {
        SIG_HASH_PREFIX = new EnumMap<>(Hash.class);
        SIG_HASH_PREFIX.put(Hash.MD5, ByteString.copyOf(new byte[]{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10}));
        SIG_HASH_PREFIX.put(Hash.SHA1, ByteString.copyOf(new byte[]{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}));
        SIG_HASH_PREFIX.put(Hash.SHA224, ByteString.copyOf(new byte[]{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}));
        SIG_HASH_PREFIX.put(Hash.SHA256, ByteString.copyOf(new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}));
        SIG_HASH_PREFIX.put(Hash.SHA384, ByteString.copyOf(new byte[]{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}));
        SIG_HASH_PREFIX.put(Hash.SHA512, ByteString.copyOf(new byte[]{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}));
    }

    /**
     * Performs a PKCS#1 v1.5 signature on previously hashed data. The hash algorithm used to hash the data is still
     * needed to perform the proper encoding. The signature will be done with the given key algorithm with the key
     * in the given slot.
     *
     * @param hashed
     * @param hashAlg
     * @param algorithm
     * @param keySlot
     * @return
     * @throws YkPivException
     * @throws IOException
     */
    public ByteString sign(ByteString hashed, Hash hashAlg, KeyAlgorithm algorithm, KeySlot keySlot) throws YkPivException {
        ByteString bytesToSign;
        if (algorithm == KeyAlgorithm.RSA_1024 || algorithm == KeyAlgorithm.RSA_2048) {
            final ByteString prefix = SIG_HASH_PREFIX.get(hashAlg);
            if (prefix == null) {
                throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlg);
            }
            byte[] prefixedHash = new byte[prefix.getLength() + hashed.getLength()];
            prefix.writeTo(0, prefixedHash, 0, prefix.getLength());
            hashed.writeTo(0, prefixedHash, prefix.getLength(), hashed.getLength());
            bytesToSign = Pkcs1v15.pad(ByteString.copyOf(prefixedHash), algorithm == KeyAlgorithm.RSA_1024 ? 128 : 256);
        } else {
            // EC methods don't need the hash algorithm prefix or padding, but we may need to truncate long hashes
            int keyLen = algorithm == KeyAlgorithm.EC_256 ? 32 : 48;
            if (hashed.getLength() <= keyLen) {
                bytesToSign = hashed;
            } else {
                bytesToSign = hashed.slice(0, keyLen);
            }
        }
        return signInternal(bytesToSign, algorithm.getYkpivAlgorithm(), keySlot.getKeyId());
    }

    private ByteString signInternal(ByteString rawIn, byte algorithm, byte key) throws YkPivException {
        return generateAuthenticate(rawIn, algorithm, key, false);
    }

    /**
     * Perform a decrypt operation of the give data with the provided key algorithm with the key in the given slot.
     * @param rawIn
     * @param algorithm
     * @param key
     * @return
     * @throws YkPivException
     */
    public ByteString decipher(ByteString rawIn, KeyAlgorithm algorithm, KeySlot key) throws YkPivException {
        return generateAuthenticate(rawIn, algorithm.getYkpivAlgorithm(), key.getKeyId(), true);
    }

    /**
     * Genearte a new key inside the yubikey in the given slot with the given key algorithm. The key will be bound with the given
     * PIN policy and touch policy.
     * @param slot
     * @param algorithm
     * @param pinPolicy Can be null in which case the device's default policy will be used.
     * @param touchPolicy Can be null in which case the device's default policy will be used.
     * @return
     * @throws YkPivException
     */
    public PublicKey generateKey(KeySlot slot, KeyAlgorithm algorithm, PinPolicy pinPolicy, TouchPolicy touchPolicy) throws YkPivException {

        List<ByteString> params = new ArrayList<>();
        params.add(SimpleAsn1.build(InternalConstants.YKPIV_ALGO_TAG, ByteString.copyOf(new byte[] {algorithm.getYkpivAlgorithm()})));
        if (pinPolicy != null && pinPolicy != PinPolicy.DEFAULT) {
            params.add(SimpleAsn1.build(InternalConstants.YKPIV_PINPOLICY_TAG, ByteString.copyOf(new byte[] {pinPolicy.getYkpivPinPolicy()})));
        }
        if (touchPolicy != null && touchPolicy != TouchPolicy.DEFAULT) {
            params.add(SimpleAsn1.build(InternalConstants.YKPIV_TOUCHPOLICY_TAG, ByteString.copyOf(new byte[] {touchPolicy.getYkpivTouchPolicy()})));
        }
        final ByteString data = SimpleAsn1.build((byte)0xac, params.toArray(new ByteString[params.size()]));

        ByteString output = transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_GENERATE_ASYMMETRIC, 0x00, slot.getKeyId()), data);
        SimpleAsn1.Asn1Object result = SimpleAsn1.decodeSingleton(output);

        try {
            if (algorithm == KeyAlgorithm.RSA_1024 || algorithm == KeyAlgorithm.RSA_2048) {
                if (result.getTag() != 0x49) {
                    throw new YkPivException("Got unexpected tag from generated key response: " + result.getTag());
                }
                List<SimpleAsn1.Asn1Object> parts = SimpleAsn1.decode(result.getData());
                if (parts.size() != 2) {
                    throw new YkPivException("Got unexpected number of parts from RSA key response: " + parts.size());
                }
                if (parts.get(0).getTag() != 0x81) {
                    throw new YkPivException("Got unexpected tag on first RSA part: " + parts.get(0).getTag());
                }
                if (parts.get(1).getTag() != 0x82) {
                    throw new YkPivException("Got unexpected tag on second RSA part: " + parts.get(1).getTag());
                }
                BigInteger n = new BigInteger(1, parts.get(0).getData().toByteArray());
                BigInteger e = new BigInteger(1, parts.get(1).getData().toByteArray());

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
            } else if (algorithm == KeyAlgorithm.EC_256 || algorithm == KeyAlgorithm.EC_384) {
                if (result.getTag() != 0x49) {
                    throw new YkPivException("Got unexpected tag from generated key response: " + result.getTag());
                }
                List<SimpleAsn1.Asn1Object> parts = SimpleAsn1.decode(result.getData());
                if (parts.size() != 1) {
                    throw new YkPivException("Got unexpected number of parts from EC key response: " + parts.size());
                }
                final ByteString ecData = parts.get(0).getData();
                BigInteger pubX, pubY;
                if (algorithm == KeyAlgorithm.EC_256) {
                    if (ecData.getLength() != 65) {
                        throw new YkPivException("EC public key point is expected to be exactly 65 bytes long.");
                    }
                    pubX = new BigInteger(1, ecData.slice(1, 32).toByteArray());
                    pubY = new BigInteger(1, ecData.slice(33, 32).toByteArray());
                } else if (algorithm == KeyAlgorithm.EC_384) {
                    if (ecData.getLength() != 97) {
                        throw new YkPivException("EC public key point is expected to be exactly 97 bytes long.");
                    }
                    pubX = new BigInteger(1, ecData.slice(1, 48).toByteArray());
                    pubY = new BigInteger(1, ecData.slice(49, 48).toByteArray());
                } else {
                    throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
                }

                String curveName;
                if (algorithm == KeyAlgorithm.EC_256) {
                    curveName = "secp256r1";
                } else if (algorithm == KeyAlgorithm.EC_384) {
                    curveName = "secp384r1";
                } else {
                    throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
                }

                // This seems to be the only Java public API method of getting a named curve. :(
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec(curveName));
                KeyPair keyPair = kpg.generateKeyPair();
                ECParameterSpec curveSpec = ((ECPublicKey)keyPair.getPublic()).getParams();

                KeyFactory keyFactory = KeyFactory.getInstance("EC");
                return keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(pubX, pubY), curveSpec));
            } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ByteString magnitude(BigInteger b) {
        byte[] bytes = b.toByteArray();
        if (bytes[0] == 0x00) {
            return ByteString.copyOf(bytes, 1, bytes.length-1);
        }
        return ByteString.copyOf(bytes);
    }

    /**
     * Import a private key into the given key slot. The key will be bound to the given pinPolicy and touchPolicy.
     * @param keySlot
     * @param privateKey
     * @param pinPolicy Can be null in which case the device's default policy will be used.
     * @param touchPolicy Can be null in which case the device's default policy will be used.
     * @throws YkPivException
     */
    public void importPrivateKey(KeySlot keySlot, PrivateKey privateKey, PinPolicy pinPolicy, TouchPolicy touchPolicy) throws YkPivException {

        try {
            byte algorithm;
            List<ByteString> params = new ArrayList<>();
            byte paramTag;

            if (privateKey instanceof RSAPrivateKey) {
                if (!(privateKey instanceof RSAPrivateCrtKey)) {
                    throw new IllegalArgumentException("Only instances of RSA CRT keys can be imported.");
                }
                RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;

                int keyLength = rsaPrivateKey.getModulus().bitLength()/8;
                switch (keyLength) {
                    case 128:
                        algorithm = InternalConstants.YKPIV_ALGO_RSA1024;
                        break;
                    case 256:
                        algorithm = InternalConstants.YKPIV_ALGO_RSA2048;
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported key length: " + keyLength);
                }

                paramTag = 0x01;
                params.add(magnitude(rsaPrivateKey.getPrimeP()));
                params.add(magnitude(rsaPrivateKey.getPrimeQ()));
                params.add(magnitude(rsaPrivateKey.getPrimeExponentP()));
                params.add(magnitude(rsaPrivateKey.getPrimeExponentQ()));
                params.add(magnitude(rsaPrivateKey.getCrtCoefficient()));
            } else if (privateKey instanceof ECPrivateKey) {
                ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;

                int keyLength = ecPrivateKey.getParams().getCurve().getField().getFieldSize()/8;
                switch (keyLength) {
                    case 32:
                        algorithm = InternalConstants.YKPIV_ALGO_ECCP256;
                        break;
                    case 48:
                        algorithm = InternalConstants.YKPIV_ALGO_ECCP384;
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported key length: " + keyLength);
                }

                paramTag = 0x06;
                params.add(magnitude(ecPrivateKey.getS()));
            } else {
                throw new IllegalArgumentException("Unsupported private key: " + privateKey.getClass().getName());
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
            for (int i = 0; i < params.size(); i++) {
                SimpleAsn1.build((byte)(paramTag+i), params.get(i)).writeTo(baos);
            }
            if (pinPolicy != null && pinPolicy != PinPolicy.DEFAULT) {
                baos.write(InternalConstants.YKPIV_PINPOLICY_TAG);
                baos.write(1);
                baos.write(pinPolicy.getYkpivPinPolicy());
            }
            if (touchPolicy != null && touchPolicy != TouchPolicy.DEFAULT) {
                baos.write(InternalConstants.YKPIV_TOUCHPOLICY_TAG);
                baos.write(1);
                baos.write(touchPolicy.getYkpivTouchPolicy());
            }

            transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_IMPORT_KEY, algorithm, keySlot.getKeyId()),
                    ByteString.copyOf(baos.toByteArray()));

        } catch (IOException e) {
            throw new IllegalStateException("IOException writing to ByteArrayOutputStream.", e);
        }
    }

    private static void writeObjectId(OutputStream os, int objectId) throws IOException {
        os.write(0x5c);
        if (objectId == InternalConstants.YKPIV_OBJ_DISCOVERY) {
            os.write(1);
            os.write(InternalConstants.YKPIV_OBJ_DISCOVERY);
        } else if(objectId > 0xffff && objectId <= 0xffffff) {
            os.write(3);
            os.write((byte)((objectId >> 16) & 0xff));
            os.write((byte)((objectId >> 8) & 0xff));
            os.write((byte)(objectId & 0xff));
        }
    }

    private void saveObject(int objectId, ByteString data) throws YkPivException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(data.getLength() + 9);
            writeObjectId(baos, objectId);
            SimpleAsn1.build((byte)0x53, data).writeTo(baos);

            transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_PUT_DATA, 0x3f, 0xff),
                    ByteString.copyOf(baos.toByteArray()));
        } catch (IOException e) {
            throw new IllegalStateException("Got IOException writing to ByteArrayOutputStream.", e);
        }
    }

    private ByteString fetchObject(int objectId) throws YkPivException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(5);
            writeObjectId(baos, objectId);
            ByteString output = transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_GET_DATA, 0x3f, 0xff),
                    ByteString.copyOf(baos.toByteArray()));
            return SimpleAsn1.decodeSingleton(output).getData();
        } catch (IOException e) {
            throw new IllegalStateException("Got IOException writing to ByteArrayOutputStream.", e);
        }
    }

    private void changePinInternal(String currentPin, String newPin, byte instruction, byte p2) throws YkPivException {
        final byte[] currentPinBytes = currentPin.getBytes(StandardCharsets.UTF_8);
        final byte[] newPinBytes = newPin.getBytes(StandardCharsets.UTF_8);

        if (currentPinBytes.length > 8) {
            throw new IllegalArgumentException("Current PIN length too long: " + currentPinBytes.length);
        }
        if (newPinBytes.length > 8) {
            throw new IllegalArgumentException("New PIN length too long: " + newPinBytes.length);
        }
        final byte[] data = new byte[16];
        System.arraycopy(currentPinBytes, 0, data, 0, currentPinBytes.length);
        for (int i = currentPinBytes.length; i < 8; i++) {
            data[i] = (byte)0xff;
        }
        System.arraycopy(newPinBytes, 0, data, 8, newPinBytes.length);
        for (int i = newPinBytes.length; i < 8; i++) {
            data[8+i] = (byte)0xff;
        }

        ResponseAPDU response;
        try {
            response = card.getBasicChannel().transmit(new CommandAPDU(0x00, instruction, 0, p2, data));
        } catch (CardException e) {
            throw new YkPivException("Unable to communicate with card to change PIN.", e);
        }
        if (response.getSW() != InternalConstants.SW_SUCCESS) {
            if((response.getSW() >> 8) == 0x63) {
                throw new YkPivException("Wrong PIN: " + (response.getSW() & 0xf) + " tries remaining");
            } else if(response.getSW() == InternalConstants.SW_ERR_AUTH_BLOCKED) {
                throw new YkPivException("PIN is locked!");
            } else {
                throw new YkPivException("Failed changing pin, token response code: " + response.getSW());
            }
        }
    }

    /**
     * Changes the current PIN for the device.
     * @param currentPin
     * @param newPin
     * @throws YkPivException
     */
    public void changePin(String currentPin, String newPin) throws YkPivException {
        changePinInternal(currentPin, newPin, InternalConstants.YKPIV_INS_CHANGE_REFERENCE, (byte)0x80);
    }

    /**
     * Changes the current PUK for the device.
     * @param currentPuk
     * @param newPuk
     * @throws YkPivException
     */
    public void changePuk(String currentPuk, String newPuk) throws YkPivException {
        changePinInternal(currentPuk, newPuk, InternalConstants.YKPIV_INS_CHANGE_REFERENCE, (byte)0x81);
    }

    /**
     * Unblocks the PIN for the device, resetting it to the new value.
     * @param currentPuk
     * @param newPin
     * @throws YkPivException
     */
    public void unblockPin(String currentPuk, String newPin) throws YkPivException {
        changePinInternal(currentPuk, newPin, InternalConstants.YKPIV_INS_RESET_RETRY, (byte)0x80);
    }

    /**
     * Saves the provide certificate into the given key slot.
     * @param slot
     * @param cert
     * @throws YkPivException
     */
    public void saveCertificate(KeySlot slot, Certificate cert) throws YkPivException {
        try {
            final ByteString encoded = ByteString.copyOf(cert.getEncoded());
            final ByteArrayOutputStream baos = new ByteArrayOutputStream(encoded.getLength() + 8);
            SimpleAsn1.build((byte)0x70, encoded).writeTo(baos);
            SimpleAsn1.build((byte)0x71, ByteString.copyOf(new byte[]{0x00})).writeTo(baos);
            SimpleAsn1.build((byte)0x72, ByteString.EMPTY).writeTo(baos);
            saveObject(slot.getObjectId(), ByteString.copyOf(baos.toByteArray()));
        } catch (CertificateEncodingException | IOException e) {
            throw new IllegalStateException("Unable to encode certificate", e);
        }
    }

    /**
     * Feteches the certificate saved in the given key slot. If there is no certificate in
     * the slot this will return null.
     *
     * @param slot
     * @return
     * @throws YkPivException
     */
    public X509Certificate readCertificate(KeySlot slot) throws YkPivException {
        List<SimpleAsn1.Asn1Object> objects = SimpleAsn1.decode(fetchObject(slot.getObjectId()));
        if (objects == null || objects.size() == 0) {
            return null;
        }
        if (objects.size() != 3 || objects.get(0).getTag() != 0x70) {
            throw new IllegalStateException("Unable to parse fetch object result.");
        }
        try {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            try (InputStream inputStream = objects.get(0).getData().newInputStream()) {
                return (X509Certificate) certificateFactory.generateCertificate(inputStream);
            }
        } catch (CertificateException | IOException e) {
            throw new YkPivException("Unable to parse fetched certificate.", e);
        }
    }

    /**
     * Deletes the certificate (or any other object) in the given key slot.
     * @param slot
     * @throws YkPivException
     */
    public void deleteCertificate(KeySlot slot) throws YkPivException {
        saveObject(slot.getObjectId(), ByteString.EMPTY);
    }

    /**
     * Generates an attestation certificate of the key in the given key slot.
     * @param slot
     * @return
     * @throws YkPivException
     */
    public X509Certificate attest(KeySlot slot) throws YkPivException {
        ByteString output = transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_ATTEST, slot.getKeyId(), 0x00),
                ByteString.copyOf(new byte[] {0x00}));
        if (output.getLength() == 0) {
            return null;
        }
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            try (InputStream inputStream = output.newInputStream()) {
                return (X509Certificate) certificateFactory.generateCertificate(inputStream);
            }
        } catch (CertificateException | IOException e) {
            throw new IllegalStateException("Unable to parse attestation certificate.", e);
        }
    }
}
