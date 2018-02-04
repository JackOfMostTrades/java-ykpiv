package com.github.jackofmosttrades.ykpiv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SimpleAsn1 {
    public static class Asn1Object {
        private final int tag;
        private final byte[] data;

        public Asn1Object(int tag, byte[] data) {
            this.tag = tag;
            this.data = data;
        }

        public int getTag() {
            return tag;
        }

        public byte[] getData() {
            return data;
        }
    }

    public static byte[] build(byte tag, byte[] ... data) {
        // Intentionally do not support long tags

        int length = 0;
        for (byte[] datum : data) {
            length += datum.length;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream(length+4);
        baos.write(tag);
        if(length < 0x80) {
            baos.write((byte)length);
        } else if (length < 0xff) {
            baos.write((byte)0x81);
            baos.write(length);
        } else {
            baos.write((byte)0x82);
            baos.write((byte) ((length >> 8) & 0xff));
            baos.write((byte) (length & 0xff));
        }

        try {
            for (byte[] datum : data) {
                baos.write(datum);
            }
        } catch (IOException e){
            throw new IllegalStateException(e);
        }

        return baos.toByteArray();
    }

    public static List<Asn1Object> decode(byte[] input) {
        if (input == null || input.length == 0) {
            return null;
        }

        List<Asn1Object> objects = new ArrayList<>();
        int restIndex = 0;
        while (restIndex < input.length) {
            int index = restIndex;
            int tag = input[index] & 0xff;
            index += 1;
            if ((tag & 0x1f) == 0x1f) {
                tag = 0;
                int octet;
                do {
                    octet = input[index] & 0xff;
                    index += 1;
                    tag = (tag << 8) + (octet & 0x7f);
                } while ((octet & 0x80) != 0);
            }

            int length = input[index] & 0xff;
            index += 1;
            if ((length & 0x80) != 0) {
                int n = (length & 0x7f);
                length = 0;
                for (int i = 0; i < n; i++) {
                    length = (length << 8) + (input[index+i] & 0xff);
                }
                index += n;
            }
            if (index + length > input.length) {
                throw new IllegalArgumentException("Length descriptor goes beyond end of input.");
            }

            byte[] data = new byte[length];
            System.arraycopy(input, index, data, 0, length);
            objects.add(new Asn1Object(tag, data));

            restIndex = index+length;
        }

        return objects;
    }

    public static Asn1Object decodeSingleton(byte[] input) {
        if (input == null || input.length == 0) {
            return null;
        }

        List<Asn1Object> objects = decode(input);
        if (objects.size() != 1) {
            throw new IllegalArgumentException("Got multiple objects when expecting only one: " + objects.size());
        }
        return objects.get(0);
    }
}
