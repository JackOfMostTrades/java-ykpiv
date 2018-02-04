package com.github.jackofmosttrades.ykpiv;

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
