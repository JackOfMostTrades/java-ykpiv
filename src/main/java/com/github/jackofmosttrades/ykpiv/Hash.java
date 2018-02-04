package com.github.jackofmosttrades.ykpiv;

/**
 * Represents hash algorithms known to the ykpiv library.
 */
public enum Hash {
    MD5("MD5"),
    SHA1("SHA-1"),
    SHA224("SHA-224"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512");

    private final String jceAlgorithmName;

    private Hash(String jceAlgorithmName) {
        this.jceAlgorithmName = jceAlgorithmName;
    }

    public String getJceAlgorithmName() {
        return jceAlgorithmName;
    }
}
