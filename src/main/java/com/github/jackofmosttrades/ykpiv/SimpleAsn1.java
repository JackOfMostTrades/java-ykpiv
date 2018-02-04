package com.github.jackofmosttrades.ykpiv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides utilities for serializing and parsing simple ASN.1 structures.
 */
/* package-private */ class SimpleAsn1 {

    /**
     * Represents a parsed ASN.1 object, e.g. its tag and its raw data bytes.
     */
    public static class Asn1Object {
        private final int tag;
        private final ByteString data;

        public Asn1Object(int tag, ByteString data) {
            this.tag = tag;
            this.data = data;
        }

        public int getTag() {
            return tag;
        }

        public ByteString getData() {
            return data;
        }
    }

    /**
     * Builds a new serialized ASN.1 object.
     * @param tag The tag the object should have. Only short tags (one byte) are supported.
     * @param data The data the object will hold.
     * @return
     */
    public static ByteString build(byte tag, ByteString ... data) {
        int length = 0;
        for (ByteString datum : data) {
            length += datum.getLength();
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
            for (ByteString datum : data) {
                datum.writeTo(baos);
            }
        } catch (IOException e){
            throw new IllegalStateException(e);
        }

        return ByteString.copyOf(baos.toByteArray());
    }

    /**
     * Decodes ASN.1 objects from the input. The input may be a list of objects concatenated together, so this method
     * continues to parse out objects until it reaches the end of the input ByteString.
     * @param input
     * @return
     */
    public static List<Asn1Object> decode(ByteString input) {
        if (input == null || input.getLength() == 0) {
            return null;
        }

        List<Asn1Object> objects = new ArrayList<>();
        int restIndex = 0;
        while (restIndex < input.getLength()) {
            int index = restIndex;
            int tag = input.get(index) & 0xff;
            index += 1;
            if ((tag & 0x1f) == 0x1f) {
                tag = 0;
                int octet;
                do {
                    octet = input.get(index) & 0xff;
                    index += 1;
                    tag = (tag << 8) + (octet & 0x7f);
                } while ((octet & 0x80) != 0);
            }

            int length = input.get(index) & 0xff;
            index += 1;
            if ((length & 0x80) != 0) {
                int n = (length & 0x7f);
                length = 0;
                for (int i = 0; i < n; i++) {
                    length = (length << 8) + (input.get(index+i) & 0xff);
                }
                index += n;
            }
            if (index + length > input.getLength()) {
                throw new IllegalArgumentException("Length descriptor goes beyond end of input.");
            }

            objects.add(new Asn1Object(tag, input.slice(index, length)));
            restIndex = index+length;
        }

        return objects;
    }

    /**
     * Decodes an ASN.1 object from the input. If the input is not exactly one object then an exception will be thrown.
     * @param input
     * @return
     */
    public static Asn1Object decodeSingleton(ByteString input) {
        if (input == null || input.getLength() == 0) {
            return null;
        }

        List<Asn1Object> objects = decode(input);
        if (objects.size() != 1) {
            throw new IllegalArgumentException("Got multiple objects when expecting only one: " + objects.size());
        }
        return objects.get(0);
    }
}
