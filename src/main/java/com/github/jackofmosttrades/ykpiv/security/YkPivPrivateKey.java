package com.github.jackofmosttrades.ykpiv.security;

import com.github.jackofmosttrades.ykpiv.KeyAlgorithm;
import com.github.jackofmosttrades.ykpiv.KeySlot;
import com.github.jackofmosttrades.ykpiv.YkPiv;

import java.security.PrivateKey;

class YkPivPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 8307205839880653472L;

    private final transient YkPiv ykPiv;
    private final KeyAlgorithm keyAlgorithm;
    private final KeySlot keySlot;

    YkPivPrivateKey(YkPiv ykPiv, KeyAlgorithm keyAlgorithm, KeySlot keySlot) {
        this.ykPiv = ykPiv;
        this.keyAlgorithm = keyAlgorithm;
        this.keySlot = keySlot;
    }

    /* package-private */ YkPiv getYkPiv() {
        return ykPiv;
    }

    /* package-private */ KeyAlgorithm getKeyAlgorithm() {
        return keyAlgorithm;
    }

    /* package-private */ KeySlot getKeySlot() {
        return keySlot;
    }

    @Override
    public String getAlgorithm() {
        switch (keyAlgorithm) {
            case RSA_1024:
            case RSA_2048:
                return "RSA";
            case EC_256:
            case EC_384:
                return "EC";
            default:
                throw new IllegalStateException("Unhandled algorithm: " + keyAlgorithm);
        }
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
