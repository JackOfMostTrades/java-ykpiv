package com.github.jackofmosttrades.ykpiv.security;

import com.github.jackofmosttrades.ykpiv.ByteString;
import com.github.jackofmosttrades.ykpiv.Hash;
import com.github.jackofmosttrades.ykpiv.YkPivException;

import java.security.*;

/**
 * Provides Signature implementations that sign using YkPivPrivateKey instances.
 */
public abstract class YkPivSignature extends SignatureSpi {

    private final Hash hash;
    private final MessageDigest messageDigest;

    private YkPivPrivateKey privateKey;

    protected YkPivSignature(Hash hash) {
        this.hash = hash;
        try {
            this.messageDigest = MessageDigest.getInstance(hash.getJceAlgorithmName());
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("Only sign operation is supported.");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof YkPivPrivateKey)) {
            throw new IllegalArgumentException("Only YPivPrivateKey private keys are supported.");
        }
        this.privateKey = (YkPivPrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        messageDigest.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        messageDigest.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new IllegalStateException("YkPivSignature not initialized.");
        }
        try {
            return privateKey.getYkPiv().sign(
                    ByteString.copyOf(messageDigest.digest()), hash, privateKey.getKeyAlgorithm(), privateKey.getKeySlot())
                    .toByteArray();
        } catch (YkPivException e) {
            throw new SignatureException("Exception while trying to create signature.", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new UnsupportedOperationException("Only sign operation is supported.");
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("This implementation does not accept any parameters.");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("This implementation does not accept any parameters.");
    }

    public static class MD5withYKPIV extends YkPivSignature {
        public MD5withYKPIV() {
            super(Hash.MD5);
        }
    }

    public static class SHA1withYKPIV extends YkPivSignature {
        public SHA1withYKPIV() {
            super(Hash.SHA1);
        }
    }

    public static class SHA224withYKPIV extends YkPivSignature {
        public SHA224withYKPIV() {
            super(Hash.SHA224);
        }
    }

    public static class SHA256withYKPIV extends YkPivSignature {
        public SHA256withYKPIV() {
            super(Hash.SHA256);
        }
    }

    public static class SHA384withYKPIV extends YkPivSignature {
        public SHA384withYKPIV() {
            super(Hash.SHA384);
        }
    }

    public static class SHA512withYKPIV extends YkPivSignature {
        public SHA512withYKPIV() {
            super(Hash.SHA512);
        }
    }
}
