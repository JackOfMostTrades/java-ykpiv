package com.github.jackofmosttrades.ykpiv;

/**
 * Represents touch policies that can be used for keys generated/imported into a yubikey.
 */
public enum TouchPolicy {
    DEFAULT(InternalConstants.YKPIV_TOUCHPOLICY_DEFAULT),
    NEVER(InternalConstants.YKPIV_TOUCHPOLICY_NEVER),
    ALWAYS(InternalConstants.YKPIV_TOUCHPOLICY_ALWAYS),
    CACHED(InternalConstants.YKPIV_TOUCHPOLICY_CACHED);

    private final byte ykpivTouchPolicy;

    private TouchPolicy(byte ykpivTouchPolicy) {
        this.ykpivTouchPolicy = ykpivTouchPolicy;
    }

    /* package-private */ byte getYkpivTouchPolicy() {
        return ykpivTouchPolicy;
    }
}
