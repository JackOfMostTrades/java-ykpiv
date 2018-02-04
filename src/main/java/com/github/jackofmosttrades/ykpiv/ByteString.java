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

    /**
     * Gets the ith byte in the string.
     *
     * @param i
     * @return
     * @throws ArrayIndexOutOfBoundsException if i < 0 or i is greater than or equal to the length
     */
    public byte get(int i) {
        if (i < 0 || i >= length) {
            throw new ArrayIndexOutOfBoundsException("Invalid index: " + i);
        }
        return data[offset+i];
    }

    /**
     * Gets the length of the byte string.
     * @return
     */
    public int getLength() {
        return length;
    }

    /**
     * Creates a new copy of the data this byte string represents and returns it as a byte array.
     * @return
     */
    public byte[] toByteArray() {
        byte[] result = new byte[length];
        System.arraycopy(data, offset, result, 0, length);
        return result;
    }

    /**
     * Creates a ByteString representing the same data as the passed in array. Makes a copy, so changes to
     * input will not change the value of the returned ByteString.
     *
     * @param input
     * @return
     */
    public static ByteString copyOf(byte[] input) {
        return copyOf(input, 0, input.length);
    }

    /**
     * Creates a ByteString representing the slice of the passed in array, starting at offset and of the
     * given length. Makes a copy, so changes to input will not change the value of the returned ByteString.
     * @param input
     * @param offset
     * @param length
     * @return
     */
    public static ByteString copyOf(byte[] input, int offset, int length) {
        if (offset + length > input.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        return new ByteString(input.clone(), offset, length);
    }

    /**
     * Returns a new ByteString representing the slice. The same underlying data is used to back the new
     * ByteString, so this does not allocate new memory.
     *
     * @param offset
     * @param length
     * @return
     */
    public ByteString slice(int offset, int length) {
        if (offset < 0) {
            throw new ArrayIndexOutOfBoundsException("offset must be >= 0");
        }
        if (offset + length > this.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        return new ByteString(data, this.offset+offset, length);
    }

    /**
     * Writes the data represented by this ByteString to the output stream.
     * @param outputStream
     * @throws IOException
     */
    public void writeTo(OutputStream outputStream) throws IOException {
        writeTo(outputStream, 0, length);
    }

    /**
     * Writes the slice of data represented by this ByteString to the output stream, starting at offset
     * and of the given length.
     * @param outputStream
     * @param offset
     * @param length
     * @throws IOException
     */
    public void writeTo(OutputStream outputStream, int offset, int length) throws IOException {
        if (offset < 0) {
            throw new ArrayIndexOutOfBoundsException("offset must be >= 0");
        }
        if (offset + length > this.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        outputStream.write(data, this.offset + offset, length);
    }

    /**
     * Copies the slice of data represented by srcOffset and length to the destination buffer, starting
     * at destOffset.
     * @param srcOffset
     * @param dest
     * @param destOffset
     * @param length
     * @throws IOException
     */
    public void writeTo(int srcOffset, byte[] dest, int destOffset, int length) {
        if (srcOffset < 0) {
            throw new ArrayIndexOutOfBoundsException("srcOffset must be >= 0");
        }
        if (srcOffset + length > this.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        System.arraycopy(data, offset + srcOffset, dest, destOffset, length);
    }

    /**
     * Creates an input stream that will return the bytes represented by the ByteString.
     * @return
     */
    public InputStream newInputStream() {
        return newInputStream(0, length);
    }

    /**
     * Creates an input stream that will return the bytes represented by the slice of this ByteSTring
     * @param offset
     * @param length
     * @return
     */
    public InputStream newInputStream(int offset, int length) {
        if (offset < 0) {
            throw new ArrayIndexOutOfBoundsException("srcOffset must be >= 0");
        }
        if (offset + length > this.length) {
            throw new ArrayIndexOutOfBoundsException("Length exceeds size of input.");
        }
        return new ByteArrayInputStream(data, this.offset + offset, length);
    }

    /**
     * Returns true iff the other object is a ByteString representing the same data (of the same length).
     * @param other
     * @return
     */
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
