package com.github.jackofmosttrades.ykpiv;

/**
 * Exceptions thrown from the ykpiv library. These exceptions may represent I/O exceptions communicating with the
 * yubikey, or logical errors such as incorrect parameters.
 */
public class YkPivException extends Exception {
    public YkPivException(String message) {
        super(message);
    }

    public YkPivException(String message, Throwable cause) {
        super(message, cause);
    }
}
