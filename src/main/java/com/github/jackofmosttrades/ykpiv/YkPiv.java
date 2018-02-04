package com.github.jackofmosttrades.ykpiv;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import java.util.*;
import java.util.logging.Logger;

public class YkPiv implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(YkPiv.class.getName());

    public static final byte[] DEFAULT_MGMT_KEY = new byte[] {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
    public static final String DEFAULT_PIN = "123456";
    public static final String DEFAULT_PUK = "12345678";

    private final boolean verbose;
    private Card card;

    public YkPiv() throws YkPivException {
        this("Yubikey", false);
    }

    public YkPiv(String wanted, boolean verbose) throws YkPivException {
        this.verbose = verbose;
        this.card = null;
        connect(wanted);
    }

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
                    if (verbose) {
                        LOGGER.info(String.format("skipping reader '%s' since it doesn't match '%s'.", cardTerminal.getName(), wanted));
                    }
                    continue;
                }
            }
            if (verbose) {
                LOGGER.info(String.format("trying to connect to reader '%s'.", cardTerminal.getName()));
            }
            Card card;
            try {
                card = cardTerminal.connect("T=1");
            } catch (CardException e) {
                if (verbose) {
                    LOGGER.warning(String.format("Failed to connect to reader: %s", e.getMessage()));
                }
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
                LOGGER.warning(String.format("Failed communicating with card: %s", e.getMessage()));
                continue;
            }

            this.card = card;
            return;
        }

        throw new YkPivException("no usable reader found.");
    }

    public static class VerifyResult {
        private final boolean verified;
        private final int numRetries;

        public VerifyResult(boolean verified, int numRetries) {
            this.verified = verified;
            this.numRetries = numRetries;
        }

        public boolean isVerified() {
            return verified;
        }

        public int getNumRetries() {
            return numRetries;
        }
    }

    /**
     * Attempts to login and verify the provided pin. If the pin is valid, returns -1. Otherwise returns the number of
     * attempts left. If the PIN is null, this will return the number of attempts left without causing it to decrement.
     * @param pin
     * @return
     * @throws YkPivException
     */
    public VerifyResult verify(String pin) throws YkPivException {

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
            return new VerifyResult(true, -1);
        }
        if ((response.getSW() >> 8) == 0x63) {
            return new VerifyResult(false, response.getSW() & 0xf);
        }
        if (response.getSW() == InternalConstants.SW_ERR_AUTH_BLOCKED) {
            return new VerifyResult(false, 0);
        }
        throw new YkPivException("Unexpected SW result: " + response.getSW());
    }

    private byte[] transferData(final CommandAPDU adpu, byte[] data) throws YkPivException {
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
                if (index + max_length < data.length) {
                    send_length = max_length;
                    byte[] partialBytes = new byte[send_length];
                    System.arraycopy(data, index, partialBytes, 0, send_length);
                    partialAdpu = new CommandAPDU(0x10, adpu.getINS(), adpu.getP1(), adpu.getP2(), partialBytes);
                } else {
                    send_length = data.length - index;
                    byte[] partialBytes = new byte[send_length];
                    System.arraycopy(data, index, partialBytes, 0, send_length);
                    partialAdpu = new CommandAPDU(adpu.getCLA(), adpu.getINS(), adpu.getP1(), adpu.getP2(), partialBytes);
                }

                ResponseAPDU response = card.getBasicChannel().transmit(partialAdpu);
                sw = response.getSW();
                if (sw != InternalConstants.SW_SUCCESS && (sw >> 8) != 0x61) {
                    return baos.toByteArray();
                }
                baos.write(response.getData());

                index += send_length;
            } while (index < data.length);

            // Now read all data back
            while (sw >> 8 == 0x61) {
                ResponseAPDU response = card.getBasicChannel().transmit(new CommandAPDU(0x00, 0xc0, 0x00, 0x00));
                sw = response.getSW();
                if (sw != InternalConstants.SW_SUCCESS && sw >> 8 != 0x61) {
                    return baos.toByteArray();
                }
                baos.write(response.getData());
            }

            return baos.toByteArray();
        } catch (CardException | IOException e) {
            throw new YkPivException("Unable to transmit data to card.", e);
        } finally {
            try {
                card.endExclusive();
            } catch (CardException e) {
                LOGGER.warning("Unable to end transaction: " + e.getMessage());
            }
        }
    }

    /**
     * Authenticates to the card, using the 24-byte MGMT key.
     * @param mgmtKey
     */
    public void authencate(byte[] mgmtKey) throws YkPivException {
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
            decCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(mgmtKey, "DESede"));
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
            encCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(mgmtKey, "DESede"));
            if (!MessageDigest.isEqual(cardChallengeResp, encCipher.doFinal(ourChallange))) {
                throw new YkPivException("Failed to verify card challenge response.");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException("Unexpected exception performing crypto", e);
        } catch (CardException e) {
            throw new YkPivException("Unable to authenticate with management key.", e);
        }
    }

    public void setMgmtKey(byte[] newKey) throws YkPivException {
        setMgmtKey(newKey, false);
    }

    public void setMgmtKey(byte[] newKey, boolean requireTouch) throws YkPivException {

        if (newKey.length != 24) {
            throw new IllegalArgumentException("Management key must be exactly 24 bytes long.");
        }
        // FIXME: This skips weak key checking that's in the C ykpiv library
        final byte[] data = new byte[3+newKey.length];
        data[0] = InternalConstants.YKPIV_ALGO_3DES;
        data[1] = InternalConstants.YKPIV_KEY_CARDMGM;
        data[2] = (byte)newKey.length;
        System.arraycopy(newKey, 0, data, 3, newKey.length);

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

    private byte[] generateAuthenticate(byte[] input, byte algorithm, byte key, boolean decipher) throws YkPivException {
        int key_len = 0;
        switch(algorithm) {
            case InternalConstants.YKPIV_ALGO_RSA1024:
                key_len = 128;
                // Falls through
            case InternalConstants.YKPIV_ALGO_RSA2048:
                if(key_len == 0) {
                    key_len = 256;
                }
                if(input.length != key_len) {
                    throw new IllegalArgumentException("Input length does not match key length: " + input.length + " != " + key_len);
                }
                break;
            case InternalConstants.YKPIV_ALGO_ECCP256:
                key_len = 32;
                // Falls through
            case InternalConstants.YKPIV_ALGO_ECCP384:
                if(key_len == 0) {
                    key_len = 48;
                }
                if(!decipher && input.length > key_len) {
                    throw new IllegalArgumentException("Input length greater than key length: " + input.length + " > " + key_len);
                } else if(decipher && input.length != (key_len * 2) + 1) {
                    throw new IllegalArgumentException("Input length incorrect: " + input.length + " != " + (key_len * 2 + 1));
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        final boolean isEcAlg = (algorithm == InternalConstants.YKPIV_ALGO_ECCP256 || algorithm == InternalConstants.YKPIV_ALGO_ECCP384);
        final byte[] data = SimpleAsn1.build((byte)0x7c,
                SimpleAsn1.build((byte)0x82, new byte[0]),
                SimpleAsn1.build(isEcAlg && decipher ? (byte)0x85 : (byte)0x81, input));

        byte[] output = transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_AUTHENTICATE, algorithm, key), data);
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

    public byte[] hashAndSign(InputStream inputStream, Hash hashAlg, KeyAlgorithm algorithm, KeySlot keySlot) throws YkPivException, IOException {
        try {
            final byte[] buffer = new byte[4096];
            int n;
            MessageDigest md = MessageDigest.getInstance(hashAlg.getJceAlgorithmName());
            while ((n = inputStream.read(buffer)) > 0) {
                md.update(buffer, 0, n);
            }
            return sign(md.digest(), hashAlg, algorithm, keySlot);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Invalid hash algorithm: " + hashAlg);
        }
    }

    public byte[] hashAndSign(byte[] input, Hash hashAlg, KeyAlgorithm algorithm, KeySlot keySlot) throws YkPivException {
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlg.getJceAlgorithmName());
            return sign(md.digest(input), hashAlg, algorithm, keySlot);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Invalid hash algorithm: " + hashAlg);
        }
    }

    // https://golang.org/src/crypto/rsa/pkcs1v15.go#L204
    private static final Map<Hash, byte[]> SIG_HASH_PREFIX;
    static {
        SIG_HASH_PREFIX = new EnumMap<>(Hash.class);
        SIG_HASH_PREFIX.put(Hash.MD5, new byte[]{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10});
        SIG_HASH_PREFIX.put(Hash.SHA1, new byte[]{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14});
        SIG_HASH_PREFIX.put(Hash.SHA224, new byte[]{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c});
        SIG_HASH_PREFIX.put(Hash.SHA256, new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20});
        SIG_HASH_PREFIX.put(Hash.SHA384, new byte[]{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30});
        SIG_HASH_PREFIX.put(Hash.SHA512, new byte[]{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40});
    }

    public byte[] sign(byte[] hashed, Hash hashAlg, KeyAlgorithm algorithm, KeySlot keySlot) throws YkPivException {
        byte[] bytesToSign;
        if (algorithm == KeyAlgorithm.RSA_1024 || algorithm == KeyAlgorithm.RSA_2048) {
            final byte[] prefix = SIG_HASH_PREFIX.get(hashAlg);
            if (prefix == null) {
                throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlg);
            }
            byte[] prefixedHash = new byte[prefix.length + hashed.length];
            System.arraycopy(prefix, 0, prefixedHash, 0, prefix.length);
            System.arraycopy(hashed, 0, prefixedHash, prefix.length, hashed.length);
            bytesToSign = Pkcs1v15.pad(prefixedHash, algorithm == KeyAlgorithm.RSA_1024 ? 128 : 256);
        } else {
            // EC methods don't need the hash algorithm prefix or padding, but we may need to truncate long hashes
            int keyLen = algorithm == KeyAlgorithm.EC_256 ? 32 : 48;
            if (hashed.length <= keyLen) {
                bytesToSign = hashed;
            } else {
                bytesToSign = new byte[keyLen];
                System.arraycopy(hashed, 0, bytesToSign, 0, keyLen);
            }
        }
        return signInternal(bytesToSign, algorithm.getYkpivAlgorithm(), keySlot.getKeyId());
    }

    private byte[] signInternal(byte[] rawIn, byte algorithm, byte key) throws YkPivException {
        return generateAuthenticate(rawIn, algorithm, key, false);
    }

    public byte[] decipher(byte[] rawIn, KeyAlgorithm algorithm, KeySlot key) throws YkPivException {
        return generateAuthenticate(rawIn, algorithm.getYkpivAlgorithm(), key.getKeyId(), true);
    }

    public PublicKey generateKey(KeySlot slot, KeyAlgorithm algorithm, PinPolicy pinPolicy, TouchPolicy touchPolicy) throws YkPivException {

        List<byte[]> params = new ArrayList<>();
        params.add(SimpleAsn1.build(InternalConstants.YKPIV_ALGO_TAG, new byte[] {algorithm.getYkpivAlgorithm()}));
        if (pinPolicy != PinPolicy.DEFAULT) {
            params.add(SimpleAsn1.build(InternalConstants.YKPIV_PINPOLICY_TAG, new byte[] {pinPolicy.getYkpivPinPolicy()}));
        }
        if (touchPolicy != TouchPolicy.DEFAULT) {
            params.add(SimpleAsn1.build(InternalConstants.YKPIV_TOUCHPOLICY_TAG, new byte[] {touchPolicy.getYkpivTouchPolicy()}));
        }
        final byte[] data = SimpleAsn1.build((byte)0xac, params.toArray(new byte[params.size()][]));

        byte[] output = transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_GENERATE_ASYMMETRIC, 0x00, slot.getKeyId()), data);
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
                BigInteger n = new BigInteger(1, parts.get(0).getData());
                BigInteger e = new BigInteger(1, parts.get(1).getData());

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
                BigInteger pubX, pubY;
                if (algorithm == KeyAlgorithm.EC_256) {
                    if (parts.get(0).getData().length != 65) {
                        throw new YkPivException("EC public key point is expected to be exactly 65 bytes long.");
                    }
                    pubX = new BigInteger(1, Arrays.copyOfRange(parts.get(0).getData(), 1, 33));
                    pubY = new BigInteger(1, Arrays.copyOfRange(parts.get(0).getData(), 33, 65));
                } else if (algorithm == KeyAlgorithm.EC_384) {
                    if (parts.get(0).getData().length != 97) {
                        throw new YkPivException("EC public key point is expected to be exactly 97 bytes long.");
                    }
                    pubX = new BigInteger(1, Arrays.copyOfRange(parts.get(0).getData(), 1, 49));
                    pubY = new BigInteger(1, Arrays.copyOfRange(parts.get(0).getData(), 49, 97));
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

    private static byte[] magnitude(BigInteger b) {
        byte[] bytes = b.toByteArray();
        if (bytes[0] == 0x00) {
            byte[] output = new byte[bytes.length-1];
            System.arraycopy(bytes, 1, output, 0, output.length);
            return output;
        }
        return bytes;
    }

    public void importPrivateKey(KeySlot keySlot, PrivateKey privateKey, PinPolicy pinPolicy, TouchPolicy touchPolicy) throws YkPivException {

        try {
            byte algorithm;
            List<byte[]> params = new ArrayList<>();
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
                baos.write(SimpleAsn1.build((byte)(paramTag+i), params.get(i)));
            }
            if (pinPolicy != PinPolicy.DEFAULT) {
                baos.write(InternalConstants.YKPIV_PINPOLICY_TAG);
                baos.write(1);
                baos.write(pinPolicy.getYkpivPinPolicy());
            }
            if (touchPolicy != TouchPolicy.DEFAULT) {
                baos.write(InternalConstants.YKPIV_TOUCHPOLICY_TAG);
                baos.write(1);
                baos.write(touchPolicy.getYkpivTouchPolicy());
            }

            transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_IMPORT_KEY, algorithm, keySlot.getKeyId()), baos.toByteArray());

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

    private void saveObject(int objectId, byte[] data) throws YkPivException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length + 9);
            writeObjectId(baos, objectId);
            baos.write(SimpleAsn1.build((byte)0x53, data));

            transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_PUT_DATA, 0x3f, 0xff), baos.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("Got IOException writing to ByteArrayOutputStream.", e);
        }
    }

    private byte[] fetchObject(int objectId) throws YkPivException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(5);
            writeObjectId(baos, objectId);
            byte[] output = transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_GET_DATA, 0x3f, 0xff), baos.toByteArray());
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

    public void changePin(String currentPin, String newPin) throws YkPivException {
        changePinInternal(currentPin, newPin, InternalConstants.YKPIV_INS_CHANGE_REFERENCE, (byte)0x80);
    }

    public void changePuk(String currentPuk, String newPuk) throws YkPivException {
        changePinInternal(currentPuk, newPuk, InternalConstants.YKPIV_INS_CHANGE_REFERENCE, (byte)0x81);
    }

    public void unblockPin(String currentPuk, String newPin) throws YkPivException {
        changePinInternal(currentPuk, newPin, InternalConstants.YKPIV_INS_RESET_RETRY, (byte)0x80);
    }

    public void saveCertificate(KeySlot slot, Certificate cert) throws YkPivException {
        try {
            final byte[] encoded = cert.getEncoded();
            final ByteArrayOutputStream baos = new ByteArrayOutputStream(encoded.length + 8);
            baos.write(SimpleAsn1.build((byte)0x70, encoded));
            baos.write(SimpleAsn1.build((byte)0x71, new byte[]{0x00}));
            baos.write(SimpleAsn1.build((byte)0x72, new byte[0]));
            saveObject(slot.getObjectId(), baos.toByteArray());
        } catch (CertificateEncodingException | IOException e) {
            throw new IllegalStateException("Unable to encode certificate", e);
        }
    }
    public Certificate readCertificate(KeySlot slot) throws YkPivException {
        List<SimpleAsn1.Asn1Object> objects = SimpleAsn1.decode(fetchObject(slot.getObjectId()));
        if (objects == null || objects.size() == 0) {
            return null;
        }
        if (objects.size() != 3 || objects.get(0).getTag() != 0x70) {
            throw new IllegalStateException("Unable to parse fetch object result.");
        }
        try {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            try (ByteArrayInputStream bais = new ByteArrayInputStream(objects.get(0).getData())) {
                return certificateFactory.generateCertificate(bais);
            }
        } catch (CertificateException | IOException e) {
            throw new YkPivException("Unable to parse fetched certificate.", e);
        }
    }

    public void deleteCertificate(KeySlot slot) throws YkPivException {
        saveObject(slot.getObjectId(), new byte[0]);
    }

    public Certificate attest(KeySlot slot) throws YkPivException {
        byte[] output = transferData(new CommandAPDU(0x00, InternalConstants.YKPIV_INS_ATTEST, slot.getKeyId(), 0x00), new byte[] {0x00});
        if (output.length == 0) {
            return null;
        }
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            try (ByteArrayInputStream bais = new ByteArrayInputStream(output)) {
                return certificateFactory.generateCertificate(bais);
            }
        } catch (CertificateException | IOException e) {
            throw new IllegalStateException("Unable to parse attestation certificate.", e);
        }
    }
}
