# java-ykpiv

This is a pure Java implementation of the [ykpiv library](https://developers.yubico.com/yubico-piv-tool/) created by Yubico. Unlike other ports of the ykpiv library to other languages, this is a complete port of the ykpiv library and not a wrapper around the native library. It is implemented on top of the [Java Smart Card I/O API](https://docs.oracle.com/javase/7/docs/jre/api/security/smartcardio/spec/), so it *does not* include any JNI component. Therefore, this library should be immediately usable on all platforms that support a complete JRE.

## Usage

The main class for this library is [YkPiv](src/main/java/com/github/jackofmosttrades/ykpiv/YkPiv.java). Upon construction it creates a connection to the yubikey, and so you should close the YkPiv object to disconnect.

This is a brief example of using the library to generate a key in the Authentication slot, and sign some data with it.

```java
try (YkPiv ykPiv = new YkPiv()) {
    ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
    PublicKey publicKey = ykPiv.generateKey(KeySlot.AUTHENTICATION, keyAlgorithm, PinPolicy.NEVER, TouchPolicy.NEVER);
    ykPiv.verify(YkPiv.DEFAULT_PIN);
    byte[] signature = ykPiv.hashAndSign(data, hashAlgorithm, keyAlgorithm, KeySlot.AUTHENTICATION);
}
```
