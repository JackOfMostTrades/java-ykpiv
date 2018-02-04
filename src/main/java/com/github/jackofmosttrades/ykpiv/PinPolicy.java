package com.github.jackofmosttrades.ykpiv;

public enum PinPolicy {

    DEFAULT(InternalConstants.YKPIV_PINPOLICY_DEFAULT),
    NEVER(InternalConstants.YKPIV_PINPOLICY_NEVER),
    ONCE(InternalConstants.YKPIV_PINPOLICY_ONCE),
    ALWAYS(InternalConstants.YKPIV_PINPOLICY_ALWAYS);

    private final byte ykpivPinPolicy;

    private PinPolicy(byte ykpivPinPolicy) {
        this.ykpivPinPolicy = ykpivPinPolicy;
    }

    /* package-private */ byte getYkpivPinPolicy() {
        return ykpivPinPolicy;
    }
}
