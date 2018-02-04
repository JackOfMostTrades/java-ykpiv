package com.github.jackofmosttrades.ykpiv;

import javax.crypto.BadPaddingException;

/* package-private */ class Pkcs1v15 {

    private Pkcs1v15() {}

    // Pad a message to padLen bytes according to PKCS#1 v1.5 rules
    public static byte[] pad(byte[] message, int padLen) {
        int padBlockLen = padLen - message.length - 3;
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
        System.arraycopy(message, 0, output, padBlockLen+3, message.length);
        return output;
    }

    // Unpad a message according to PKCS#1 v1.5 rules
    public static byte[] unpad(byte[] message) throws BadPaddingException {
        if (message[0] != 0x00 || message[1] != 0x01) {
            throw new BadPaddingException();
        }
        int zeroBlockIndex = -1;
        for (int i = 2; i < message.length; i++) {
            if (message[i] == 0x00) {
                zeroBlockIndex = i;
                break;
            }
            if (message[i] != 0xFF) {
                throw new BadPaddingException();
            }
        }
        byte[] output = new byte[message.length-zeroBlockIndex-1];
        System.arraycopy(message, zeroBlockIndex+1, output, 0, output.length);
        return output;
    }
}
