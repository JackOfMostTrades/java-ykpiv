package com.github.jackofmosttrades.ykpiv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A light-weight embedded version of Google's ByteString. Represents a read-only array of bytes. Constructing
 * an instance of ByteString with copyOf() and converting back to a byte array with toByteArray() are expensive
 * operations that need to allocate new memory, but slice(...) operations just return a new view into the data.
 * This class also provides a writeTo(OutputStream) method to allow writing to an OutputStream without having to
 * create new copies of the byte array.
 */
public class ByteString {

    public static final ByteString EMPTY = ByteString.copyOf(new byte[0]);

    private final byte[] data;
    private final int offset;
    private final int length;

    private ByteString(byte[] data, int offset, int length) {
        this.data = data;
        this.offset = offset;
        this.length = length;
    }

    public byte get(int i) {
        if (i >= length) {
            throw new ArrayIndexOutOfBoundsException("Index greater than length of data.");
        }
        return data[offset+i];
    }

    public int getLength() {
        return length;
    }

    public byte[] toByteArray() {
        byte[] result = new byte[length];
        System.arraycopy(data, offset, result, 0, length);
        return result;
    }

    public static ByteString copyOf(byte[] input) {
        return copyOf(input, 0, input.length);
    }
    public static ByteString copyOf(byte[] input, int offset, int length) {
        if (offset + length > input.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        return new ByteString(input.clone(), offset, length);
    }

    public ByteString slice(int offset, int length) {
        if (offset + length > this.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        return new ByteString(data, this.offset+offset, length);
    }

    public void writeTo(OutputStream outputStream) throws IOException {
        writeTo(outputStream, 0, length);
    }
    public void writeTo(OutputStream outputStream, int offset, int length) throws IOException {
        if (offset + length > this.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        outputStream.write(data, this.offset + offset, length);
    }

    public void writeTo(int srcOffset, byte[] dest, int destOffset, int length) {
        if (srcOffset + length > this.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        System.arraycopy(data, offset + srcOffset, dest, destOffset, length);
    }

    public InputStream newInputStream() {
        return newInputStream(0, length);
    }

    public InputStream newInputStream(int offset, int length) {
        if (offset + length > this.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        return new ByteArrayInputStream(data, this.offset + offset, length);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof ByteString)) {
            return false;
        }
        ByteString bOther = (ByteString)other;
        if (this.length != bOther.length) {
            return false;
        }
        for (int i = 0; i < this.length; i++) {
            if (this.data[this.offset+i] != bOther.data[bOther.offset+i]) {
                return false;
            }
        }
        return true;
    }

    @Override
    public int hashCode() {
        int result = 1;
        for (int i = 0; i < length; i++) {
            result = 31 * result + data[offset + i];
        }

        return result;
    }
}
