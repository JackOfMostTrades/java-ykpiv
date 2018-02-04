package com.github.jackofmosttrades.ykpiv;

/**
 * Created by ihaken on 2/3/18.
 */
public enum KeyAlgorithm {
    RSA_1024(InternalConstants.YKPIV_ALGO_RSA1024),
    RSA_2048(InternalConstants.YKPIV_ALGO_RSA2048),
    EC_256(InternalConstants.YKPIV_ALGO_ECCP256),
    EC_384(InternalConstants.YKPIV_ALGO_ECCP384);

    private final byte ykpivAlgorithm;

    private KeyAlgorithm(byte ykpivAlgorithm) {
        this.ykpivAlgorithm = ykpivAlgorithm;
    }

    /* package-private */ byte getYkpivAlgorithm() {
        return ykpivAlgorithm;
    }
}
