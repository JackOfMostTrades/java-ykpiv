package com.github.jackofmosttrades.ykpiv;

/**
 * Constants of the ykpiv library. These are mostly copied from ykpiv.h, though not exclusively.
 */
/*package-private*/ class InternalConstants {
    public static final byte[] APPLICATION_ID = new byte[]{ (byte)0xa0, 0x00, 0x00, 0x03, 0x08 };

    public static final int SW_SUCCESS = 0x9000;
    public static final int SW_ERR_AUTH_BLOCKED = 0x6983;

    public static final byte YKPIV_INS_VERIFY = 0x20;
    public static final byte YKPIV_INS_CHANGE_REFERENCE = 0x24;
    public static final byte YKPIV_INS_RESET_RETRY = 0x2c;
    public static final byte YKPIV_INS_GENERATE_ASYMMETRIC = 0x47;
    public static final byte YKPIV_INS_AUTHENTICATE = (byte)0x87;
    public static final byte YKPIV_INS_GET_DATA = (byte)0xcb;
    public static final byte YKPIV_INS_PUT_DATA = (byte)0xdb;

    // Yubico vendor specific instructions
    public static final byte YKPIV_INS_SET_MGMKEY = (byte)0xff;
    public static final byte YKPIV_INS_IMPORT_KEY = (byte)0xfe;
    public static final byte YKPIV_INS_GET_VERSION = (byte)0xfd;
    public static final byte YKPIV_INS_RESET = (byte)0xfb;
    public static final byte YKPIV_INS_SET_PIN_RETRIES = (byte)0xfa;
    public static final byte YKPIV_INS_ATTEST = (byte)0xf9;

    public static final byte YKPIV_ALGO_TAG = (byte)0x80;
    public static final byte YKPIV_ALGO_3DES = 0x03;
    public static final byte YKPIV_ALGO_RSA1024 = 0x06;
    public static final byte YKPIV_ALGO_RSA2048 = 0x07;
    public static final byte YKPIV_ALGO_ECCP256 = 0x11;
    public static final byte YKPIV_ALGO_ECCP384 = 0x14;
    
    public static final byte YKPIV_PINPOLICY_TAG = (byte)0xaa;
    public static final byte YKPIV_PINPOLICY_DEFAULT = 0;
    public static final byte YKPIV_PINPOLICY_NEVER = 1;
    public static final byte YKPIV_PINPOLICY_ONCE = 2;
    public static final byte YKPIV_PINPOLICY_ALWAYS = 3;

    public static final byte YKPIV_TOUCHPOLICY_TAG = (byte)0xab;
    public static final byte YKPIV_TOUCHPOLICY_DEFAULT = 0;
    public static final byte YKPIV_TOUCHPOLICY_NEVER = 1;
    public static final byte YKPIV_TOUCHPOLICY_ALWAYS = 2;
    public static final byte YKPIV_TOUCHPOLICY_CACHED = 3;

    public static final byte YKPIV_KEY_AUTHENTICATION = (byte)0x9a;
    public static final byte YKPIV_KEY_CARDMGM = (byte)0x9b;
    public static final byte YKPIV_KEY_SIGNATURE = (byte)0x9c;
    public static final byte YKPIV_KEY_KEYMGM = (byte)0x9d;
    public static final byte YKPIV_KEY_CARDAUTH = (byte)0x9e;
    public static final byte YKPIV_KEY_RETIRED1 = (byte)0x82;
    public static final byte YKPIV_KEY_RETIRED2 = (byte)0x83;
    public static final byte YKPIV_KEY_RETIRED3 = (byte)0x84;
    public static final byte YKPIV_KEY_RETIRED4 = (byte)0x85;
    public static final byte YKPIV_KEY_RETIRED5 = (byte)0x86;
    public static final byte YKPIV_KEY_RETIRED6 = (byte)0x87;
    public static final byte YKPIV_KEY_RETIRED7 = (byte)0x88;
    public static final byte YKPIV_KEY_RETIRED8 = (byte)0x89;
    public static final byte YKPIV_KEY_RETIRED9 = (byte)0x8a;
    public static final byte YKPIV_KEY_RETIRED10 = (byte)0x8b;
    public static final byte YKPIV_KEY_RETIRED11 = (byte)0x8c;
    public static final byte YKPIV_KEY_RETIRED12 = (byte)0x8d;
    public static final byte YKPIV_KEY_RETIRED13 = (byte)0x8e;
    public static final byte YKPIV_KEY_RETIRED14 = (byte)0x8f;
    public static final byte YKPIV_KEY_RETIRED15 = (byte)0x90;
    public static final byte YKPIV_KEY_RETIRED16 = (byte)0x91;
    public static final byte YKPIV_KEY_RETIRED17 = (byte)0x92;
    public static final byte YKPIV_KEY_RETIRED18 = (byte)0x93;
    public static final byte YKPIV_KEY_RETIRED19 = (byte)0x94;
    public static final byte YKPIV_KEY_RETIRED20 = (byte)0x95;
    public static final byte YKPIV_KEY_ATTESTATION = (byte)0xf9;

    public static final int YKPIV_OBJ_CAPABILITY = 0x5fc107;
    public static final int YKPIV_OBJ_CHUID = 0x5fc102;
    public static final int YKPIV_OBJ_AUTHENTICATION = 0x5fc105 ;
    public static final int YKPIV_OBJ_FINGERPRINTS = 0x5fc103;
    public static final int YKPIV_OBJ_SECURITY = 0x5fc106;
    public static final int YKPIV_OBJ_FACIAL = 0x5fc108;
    public static final int YKPIV_OBJ_PRINTED = 0x5fc109;
    public static final int YKPIV_OBJ_SIGNATURE = 0x5fc10a ;
    public static final int YKPIV_OBJ_KEY_MANAGEMENT = 0x5fc10b ;
    public static final int YKPIV_OBJ_CARD_AUTH = 0x5fc101 ;
    public static final int YKPIV_OBJ_DISCOVERY = 0x7e;
    public static final int YKPIV_OBJ_KEY_HISTORY = 0x5fc10c;
    public static final int YKPIV_OBJ_IRIS = 0x5fc121;
;
    public static final int YKPIV_OBJ_RETIRED1  = 0x5fc10d;
    public static final int YKPIV_OBJ_RETIRED2  = 0x5fc10e;
    public static final int YKPIV_OBJ_RETIRED3  = 0x5fc10f;
    public static final int YKPIV_OBJ_RETIRED4  = 0x5fc110;
    public static final int YKPIV_OBJ_RETIRED5  = 0x5fc111;
    public static final int YKPIV_OBJ_RETIRED6  = 0x5fc112;
    public static final int YKPIV_OBJ_RETIRED7  = 0x5fc113;
    public static final int YKPIV_OBJ_RETIRED8  = 0x5fc114;
    public static final int YKPIV_OBJ_RETIRED9  = 0x5fc115;
    public static final int YKPIV_OBJ_RETIRED10 = 0x5fc116;
    public static final int YKPIV_OBJ_RETIRED11 = 0x5fc117;
    public static final int YKPIV_OBJ_RETIRED12 = 0x5fc118;
    public static final int YKPIV_OBJ_RETIRED13 = 0x5fc119;
    public static final int YKPIV_OBJ_RETIRED14 = 0x5fc11a;
    public static final int YKPIV_OBJ_RETIRED15 = 0x5fc11b;
    public static final int YKPIV_OBJ_RETIRED16 = 0x5fc11c;
    public static final int YKPIV_OBJ_RETIRED17 = 0x5fc11d;
    public static final int YKPIV_OBJ_RETIRED18 = 0x5fc11e;
    public static final int YKPIV_OBJ_RETIRED19 = 0x5fc11f;
    public static final int YKPIV_OBJ_RETIRED20 = 0x5fc120;

    public static final int YKPIV_OBJ_ATTESTATION = 0x5fff01;

}
