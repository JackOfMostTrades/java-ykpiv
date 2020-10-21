# java-ykpiv

This is a pure Java implementation of the [ykpiv library](https://developers.yubico.com/yubico-piv-tool/) created by Yubico. Unlike other ports of the ykpiv library to other languages, this is a complete port of the ykpiv library and not a wrapper around the native library. It is implemented on top of the [Java Smart Card I/O API](https://docs.oracle.com/javase/7/docs/jre/api/security/smartcardio/spec/), so it *does not* include any JNI component. Therefore, this library should be immediately usable on all platforms that support a complete JRE.

## Dependency

At present, the easiest way to include this library is by referencing the following bintray repo:

```
repositories {
    maven {
        url 'https://dl.bintray.com/jackofmosttrades/maven/'
    }
}

dependencies {
    compile 'com.github.jackofmosttrades:ykpiv:1.0'
}
```

## Usage

The main class for this library is [YkPiv](src/main/java/com/github/jackofmosttrades/ykpiv/YkPiv.java). Upon construction it creates a connection to the yubikey, and so you should close the YkPiv object to disconnect.

This is a brief example of using the library to generate a key in the Authentication slot, and sign some data with it.

```java
try (YkPiv ykPiv = new YkPiv()) {
    ykPiv.authenticate(YkPiv.DEFAULT_MGMT_KEY);
    PublicKey publicKey = ykPiv.generateKey(KeySlot.AUTHENTICATION, keyAlgorithm, PinPolicy.NEVER, TouchPolicy.NEVER);
    ykPiv.login(YkPiv.DEFAULT_PIN);
    byte[] signature = ykPiv.hashAndSign(data, hashAlgorithm, keyAlgorithm, KeySlot.AUTHENTICATION);
}
```

## Using ykpiv for TLS connections
You can use the yubikey PIV application to hold the private key used for TLS connections (on either the server or client side). The [SSLConnectionTest](src/test/java/com/github/jackofmosttrades/ykpiv/security/SslConnectionTest.java) shows an example of how to do this. In short:

```java
Security.addProvider(new YkPivSecurityProvider());

SSLContext sslContext = SSLContext.getInstance("TLS");
KeyManagerFactory kmf = KeyManagerFactory.getInstance(YkPivKeyManagerFactory.ALGORITHM);
kmf.init(YkPivKeyManagerFactory.initParameters(KeySlot.AUTHENTICATION));
sslContext.init(kmf.getKeyManagers(), null, null);

// Use this SSLContext to either create a socket directly, or e.g. with an HttpsUrlConnection
HttpsURLConnection connection = (HttpsURLConnection) new URL("https://example.com").openConnection();
connection.setSSLSocketFactory(sslContext.getSocketFactory());
```
