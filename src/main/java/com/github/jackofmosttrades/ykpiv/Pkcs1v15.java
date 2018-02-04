package com.github.jackofmosttrades.ykpiv;

import javax.crypto.BadPaddingException;

/**
 * Performs padding/unpadding according to the PKCS#1 v1.5 standard.
 */
/* package-private */ class Pkcs1v15 {

    private Pkcs1v15() {}

    // Pad a message to padLen bytes according to PKCS#1 v1.5 rules
    public static ByteString pad(ByteString message, int padLen) {
        int padBlockLen = padLen - message.getLength() - 3;
        if (padBlockLen < 8) {
            throw new IllegalArgumentException("Maximum message size is " + (padLen - 11));
        }
        byte[] output = new byte[padLen];
        output[0] = 0x00;
        output[1] = 0x01;
        for (int i = 0; i < padBlockLen; i++) {
            output[i+2] = (byte)0xFF;
        }
        output[padBlockLen+2] = 0x00;
        message.writeTo(0, output, padBlockLen+3, message.getLength());
        return ByteString.copyOf(output);
    }

    // Unpad a message according to PKCS#1 v1.5 rules
    public static ByteString unpad(ByteString message) throws BadPaddingException {
        if (message.get(0) != 0x00 || message.get(1) != 0x01) {
            throw new BadPaddingException();
        }
        int zeroBlockIndex = -1;
        for (int i = 2; i < message.getLength(); i++) {
            if (message.get(i) == 0x00) {
                zeroBlockIndex = i;
                break;
            }
            if (message.get(i) != (byte)0xFF) {
                throw new BadPaddingException();
            }
        }
        return message.slice(zeroBlockIndex+1, message.getLength()-zeroBlockIndex-1);
    }
}
