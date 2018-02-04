package com.github.jackofmosttrades.ykpiv;

/**
 * PIV key slots, which represents slots where keys and objects can be saved.
 */
public enum KeySlot {
    AUTHENTICATION(InternalConstants.YKPIV_KEY_AUTHENTICATION, InternalConstants.YKPIV_OBJ_AUTHENTICATION),
    SIGNATURE(InternalConstants.YKPIV_KEY_SIGNATURE, InternalConstants.YKPIV_OBJ_SIGNATURE),
    KEY_MANAGEMENT(InternalConstants.YKPIV_KEY_KEYMGM, InternalConstants.YKPIV_OBJ_KEY_MANAGEMENT),
    CARD_AUTH(InternalConstants.YKPIV_KEY_CARDAUTH, InternalConstants.YKPIV_OBJ_CARD_AUTH),
    ATTESTATION(InternalConstants.YKPIV_KEY_ATTESTATION, InternalConstants.YKPIV_OBJ_ATTESTATION),
    RETIRED1(InternalConstants.YKPIV_KEY_RETIRED1, InternalConstants.YKPIV_OBJ_RETIRED1),
    RETIRED2(InternalConstants.YKPIV_KEY_RETIRED2, InternalConstants.YKPIV_OBJ_RETIRED2),
    RETIRED3(InternalConstants.YKPIV_KEY_RETIRED3, InternalConstants.YKPIV_OBJ_RETIRED3),
    RETIRED4(InternalConstants.YKPIV_KEY_RETIRED4, InternalConstants.YKPIV_OBJ_RETIRED4),
    RETIRED5(InternalConstants.YKPIV_KEY_RETIRED5, InternalConstants.YKPIV_OBJ_RETIRED5),
    RETIRED6(InternalConstants.YKPIV_KEY_RETIRED6, InternalConstants.YKPIV_OBJ_RETIRED6),
    RETIRED7(InternalConstants.YKPIV_KEY_RETIRED7, InternalConstants.YKPIV_OBJ_RETIRED7),
    RETIRED8(InternalConstants.YKPIV_KEY_RETIRED8, InternalConstants.YKPIV_OBJ_RETIRED8),
    RETIRED9(InternalConstants.YKPIV_KEY_RETIRED9, InternalConstants.YKPIV_OBJ_RETIRED9),
    RETIRED10(InternalConstants.YKPIV_KEY_RETIRED10, InternalConstants.YKPIV_OBJ_RETIRED10),
    RETIRED11(InternalConstants.YKPIV_KEY_RETIRED11, InternalConstants.YKPIV_OBJ_RETIRED11),
    RETIRED12(InternalConstants.YKPIV_KEY_RETIRED12, InternalConstants.YKPIV_OBJ_RETIRED12),
    RETIRED13(InternalConstants.YKPIV_KEY_RETIRED13, InternalConstants.YKPIV_OBJ_RETIRED13),
    RETIRED14(InternalConstants.YKPIV_KEY_RETIRED14, InternalConstants.YKPIV_OBJ_RETIRED14),
    RETIRED15(InternalConstants.YKPIV_KEY_RETIRED15, InternalConstants.YKPIV_OBJ_RETIRED15),
    RETIRED16(InternalConstants.YKPIV_KEY_RETIRED16, InternalConstants.YKPIV_OBJ_RETIRED16),
    RETIRED17(InternalConstants.YKPIV_KEY_RETIRED17, InternalConstants.YKPIV_OBJ_RETIRED17),
    RETIRED18(InternalConstants.YKPIV_KEY_RETIRED18, InternalConstants.YKPIV_OBJ_RETIRED18),
    RETIRED19(InternalConstants.YKPIV_KEY_RETIRED19, InternalConstants.YKPIV_OBJ_RETIRED19),
    RETIRED20(InternalConstants.YKPIV_KEY_RETIRED20, InternalConstants.YKPIV_OBJ_RETIRED20);

    private final byte keyId;
    private final int objectId;

    KeySlot(byte keyId, int objectId) {
        this.keyId = keyId;
        this.objectId = objectId;
    }

    /* package-private */ byte getKeyId() {
        return keyId;
    }

    /* package-private */ int getObjectId() {
        return objectId;
    }
}
