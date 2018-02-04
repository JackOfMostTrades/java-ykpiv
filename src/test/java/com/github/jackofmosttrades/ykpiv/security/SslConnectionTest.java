package com.github.jackofmosttrades.ykpiv.security;

import com.github.jackofmosttrades.ykpiv.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class SslConnectionTest {

    @BeforeClass
    public static void setup() {
        Security.addProvider(new YkPivSecurityProvider());
    }

    private static X509CertificateHolder mintCert(X500Name subject, X500Name issuer, PublicKey publicKey, PrivateKey issuerKey) throws OperatorCreationException {
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuer,
                BigInteger.ONE,
                Date.from(Instant.now().minus(1, ChronoUnit.HOURS)),
                Date.from(Instant.now().plus(1, ChronoUnit.DAYS)),
                subject,
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded())
        );
        return certGen.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey));
    }

    /**
     * Test an SSLContext where the server private key is stored on the yubikey
     * @throws Exception
     */
    @Test
    public void testYkPivServer() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();

        final X500Name caName = new X500Name("CN=Test CA");
        X509CertificateHolder caCert = mintCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate());

        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
            PublicKey publicKey = ykPiv.generateKey(KeySlot.AUTHENTICATION, KeyAlgorithm.RSA_2048, PinPolicy.NEVER, TouchPolicy.NEVER);
            X509CertificateHolder leafCert = mintCert(new X500Name("CN=localhost"), caName, publicKey, caKeyPair.getPrivate());
            ykPiv.saveCertificate(KeySlot.AUTHENTICATION, new JcaX509CertificateConverter().getCertificate(leafCert));
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(YkPivKeyManagerFactory.ALGORITHM);
        kmf.init(YkPivKeyManagerFactory.initParameters(KeySlot.AUTHENTICATION));
        sslContext.init(kmf.getKeyManagers(), null, null);

        try (EchoServer server = new EchoServer(sslContext, false)) {
            SSLContext clientContext = SSLContext.getInstance("TLS");
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("1", new JcaX509CertificateConverter().getCertificate(caCert));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            clientContext.init(null, tmf.getTrustManagers(), null);

            try (Socket socket = clientContext.getSocketFactory().createSocket("localhost", server.getPort())) {
                try (InputStream inputStream = socket.getInputStream();
                     OutputStream outputStream = socket.getOutputStream()) {
                    outputStream.write(42);
                    int b = inputStream.read();
                    Assert.assertEquals(42, b);
                }
            }
        }
    }

    /**
     * Test an SSLContext where the client private key is stored on the yubikey
     * @throws Exception
     */
    @Test
    public void testYkPivClient() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair serverCaKp = kpg.generateKeyPair();

        final X500Name serverCaName = new X500Name("CN=Test Server CA");
        X509CertificateHolder serverCaCert = mintCert(serverCaName, serverCaName, serverCaKp.getPublic(), serverCaKp.getPrivate());

        KeyPair serverLeafPair = kpg.generateKeyPair();
        X509CertificateHolder serverCert = mintCert(new X500Name("CN=localhost"), serverCaName, serverLeafPair.getPublic(), serverCaKp.getPrivate());

        KeyPair clientCaKp = kpg.generateKeyPair();
        final X500Name clientCaName = new X500Name("CN=Test Client CA");
        X509CertificateHolder clientCaCert = mintCert(clientCaName, clientCaName, clientCaKp.getPublic(), clientCaKp.getPrivate());

        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
            PublicKey publicKey = ykPiv.generateKey(KeySlot.AUTHENTICATION, KeyAlgorithm.RSA_2048, PinPolicy.NEVER, TouchPolicy.NEVER);
            X509CertificateHolder leafCert = mintCert(new X500Name("CN=My Client"), clientCaName, publicKey, clientCaKp.getPrivate());
            ykPiv.saveCertificate(KeySlot.AUTHENTICATION, new JcaX509CertificateConverter().getCertificate(leafCert));
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyStore serverKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
        serverKeystore.load(null, null);
        serverKeystore.setKeyEntry("1", serverLeafPair.getPrivate(), "password".toCharArray(),
                new Certificate[] { new JcaX509CertificateConverter().getCertificate(serverCert),
                        new JcaX509CertificateConverter().getCertificate(serverCaCert) });
        kmf.init(serverKeystore, "password".toCharArray());
        KeyStore serverTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        serverTrustStore.load(null, null);
        serverTrustStore.setCertificateEntry("1", new JcaX509CertificateConverter().getCertificate(clientCaCert));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(serverTrustStore);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        try (EchoServer server = new EchoServer(sslContext, true)) {
            SSLContext clientContext = SSLContext.getInstance("TLS");
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("1", new JcaX509CertificateConverter().getCertificate(serverCaCert));
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            kmf = KeyManagerFactory.getInstance(YkPivKeyManagerFactory.ALGORITHM);
            kmf.init(YkPivKeyManagerFactory.initParameters(KeySlot.AUTHENTICATION));
            clientContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            try (Socket socket = clientContext.getSocketFactory().createSocket("localhost", server.getPort())) {
                try (InputStream inputStream = socket.getInputStream();
                     OutputStream outputStream = socket.getOutputStream()) {
                    outputStream.write(42);
                    int b = inputStream.read();
                    Assert.assertEquals(42, b);
                }
            }
        }
    }
}
