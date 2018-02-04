package com.github.jackofmosttrades.ykpiv;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Base64;

/**
 * WARNING! This test runs against whatever yubikey is actually plugged into your system! It will overwrite existing
 * keys, certificates, reset your PIN, etc. Make sure you don't run this against a key actually in use!
 *
 * In order to run tests, this assumes your yubikey PIV application is in a default state, with default PIN, PUK, and
 * management key.
 */
public class YkPivTest {

    @Test
    public void testVerify() throws YkPivException {
        try (YkPiv ykPiv = new YkPiv()) {
            YkPiv.VerifyResult result = ykPiv.verify(YkPiv.DEFAULT_PIN);
            Assert.assertEquals(true, result.isVerified());
            Assert.assertEquals(-1, result.getNumRetries());
        }

        try (YkPiv ykPiv = new YkPiv()) {
            YkPiv.VerifyResult result = ykPiv.verify(null);
            Assert.assertEquals(false, result.isVerified());
            Assert.assertEquals(3, result.getNumRetries());
            result = ykPiv.verify("111111");
            Assert.assertEquals(false, result.isVerified());
            Assert.assertEquals(2, result.getNumRetries());
            result = ykPiv.verify(null);
            Assert.assertEquals(false, result.isVerified());
            Assert.assertEquals(2, result.getNumRetries());
        }

        try (YkPiv ykPiv = new YkPiv()) {
            YkPiv.VerifyResult result = ykPiv.verify(YkPiv.DEFAULT_PIN);
            Assert.assertEquals(true, result.isVerified());
            Assert.assertEquals(-1, result.getNumRetries());
        }
    }

    @Test
    public void testSetMgmtKey() throws YkPivException {
        final byte[] ALT_MGMT_KEY = new byte[]{11,12,13,14,15,16,17,18,11,12,13,14,15,16,17,18,11,12,13,14,15,16,17,18};

        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);

            ykPiv.setMgmtKey(ALT_MGMT_KEY);
            ykPiv.authencate(ALT_MGMT_KEY);
            try {
                ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
                Assert.fail("Should have thrown an exception.");
            } catch (YkPivException e) {
                Assert.assertNotNull(e);
            }

            ykPiv.authencate(ALT_MGMT_KEY);
            ykPiv.setMgmtKey(YkPiv.DEFAULT_MGMT_KEY);
            ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
        }
    }

    @Test
    public void testGetVersion() throws YkPivException {
        try (YkPiv ykPiv = new YkPiv()) {
            Assert.assertEquals("4.3.3", ykPiv.getVersion());
        }
    }

    @Test
    public void testGenerateSignAndVerify() throws YkPivException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        runTestGenerateSignAndVerify(KeyAlgorithm.RSA_1024, Hash.SHA1, "SHA1withRSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.RSA_1024, Hash.SHA256, "SHA256withRSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.RSA_1024, Hash.SHA512, "SHA512withRSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.RSA_2048, Hash.SHA1, "SHA1withRSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.RSA_2048, Hash.SHA256, "SHA256withRSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.RSA_2048, Hash.SHA512, "SHA512withRSA");

        runTestGenerateSignAndVerify(KeyAlgorithm.EC_256, Hash.SHA1, "SHA1withECDSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.EC_256, Hash.SHA256, "SHA256withECDSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.EC_256, Hash.SHA512, "SHA512withECDSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.EC_384, Hash.SHA1, "SHA1withECDSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.EC_384, Hash.SHA256, "SHA256withECDSA");
        runTestGenerateSignAndVerify(KeyAlgorithm.EC_384, Hash.SHA512, "SHA512withECDSA");
    }

    private void runTestGenerateSignAndVerify(KeyAlgorithm keyAlgorithm, Hash hashAlgorithm, String jceAlgorithm) throws YkPivException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final byte[] data = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
            PublicKey publicKey = ykPiv.generateKey(KeySlot.AUTHENTICATION, keyAlgorithm, PinPolicy.NEVER, TouchPolicy.NEVER);
            ykPiv.verify(YkPiv.DEFAULT_PIN);
            byte[] signature = ykPiv.hashAndSign(data, hashAlgorithm, keyAlgorithm, KeySlot.AUTHENTICATION);
            Signature sig = Signature.getInstance(jceAlgorithm);
            sig.initVerify(publicKey);
            sig.update(data);
            Assert.assertTrue(sig.verify(signature));
        }
    }

    @Test
    public void testImportSignAndVerify() throws YkPivException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        runTestImportSignAndVerify(KeyAlgorithm.RSA_1024, Hash.SHA1, "SHA1withRSA");
        runTestImportSignAndVerify(KeyAlgorithm.RSA_1024, Hash.SHA256, "SHA256withRSA");
        runTestImportSignAndVerify(KeyAlgorithm.RSA_1024, Hash.SHA512, "SHA512withRSA");
        runTestImportSignAndVerify(KeyAlgorithm.RSA_2048, Hash.SHA1, "SHA1withRSA");
        runTestImportSignAndVerify(KeyAlgorithm.RSA_2048, Hash.SHA256, "SHA256withRSA");
        runTestImportSignAndVerify(KeyAlgorithm.RSA_2048, Hash.SHA512, "SHA512withRSA");

        runTestImportSignAndVerify(KeyAlgorithm.EC_256, Hash.SHA1, "SHA1withECDSA");
        runTestImportSignAndVerify(KeyAlgorithm.EC_256, Hash.SHA256, "SHA256withECDSA");
        runTestImportSignAndVerify(KeyAlgorithm.EC_256, Hash.SHA512, "SHA512withECDSA");
        runTestImportSignAndVerify(KeyAlgorithm.EC_384, Hash.SHA1, "SHA1withECDSA");
        runTestImportSignAndVerify(KeyAlgorithm.EC_384, Hash.SHA256, "SHA256withECDSA");
        runTestImportSignAndVerify(KeyAlgorithm.EC_384, Hash.SHA512, "SHA512withECDSA");
    }

    private void runTestImportSignAndVerify(KeyAlgorithm keyAlgorithm, Hash hashAlgorithm, String jceAlgorithm) throws YkPivException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String keyType;
        int keySize;
        
        switch (keyAlgorithm) {
            case RSA_1024:
                keyType = "RSA";
                keySize = 1024;
                break;
            case RSA_2048:
                keyType = "RSA";
                keySize = 2048;
                break;
            case EC_256:
                keyType = "EC";
                keySize = 256;
                break;
            case EC_384:
                keyType = "EC";
                keySize = 384;
                break;
            default:
                throw new IllegalArgumentException("Unsupported key algorithm: " + keyAlgorithm);
        }
        
        final byte[] data = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        try (YkPiv ykPiv = new YkPiv()) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyType);
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
            ykPiv.importPrivateKey(KeySlot.AUTHENTICATION, keyPair.getPrivate(), PinPolicy.NEVER, TouchPolicy.NEVER);
            ykPiv.verify(YkPiv.DEFAULT_PIN);
            byte[] signature = ykPiv.hashAndSign(data, hashAlgorithm, keyAlgorithm, KeySlot.AUTHENTICATION);
            Signature sig = Signature.getInstance(jceAlgorithm);
            sig.initVerify(keyPair.getPublic());
            sig.update(data);
            Assert.assertTrue(sig.verify(signature));
        }
    }

    // openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=Test/'
    private static final String TEST_CERT_DER = "MIIC9DCCAdygAwIBAgIJAIYBK8ZwpG3bMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRlc3QwHhcNMTgwMjA0MDc0NDEwWhcNMTkwMjA0MDc0NDEwWjAPMQ0wCwYDVQQDDARUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokAOtFZY2cIvHifKB6fmd5fNV+qq62PvvqKv9fzsaTEDLYriIV40164gUOV6GqTgoWdFgF+A89WVdWoyAR0UDy+rMaoKQ/+TS5rINsUwSGG2Z3jbQqfG1XyMSXqRbEHTT8OGh6sMWj0yaL3kpgMIXPYALxp1pLPGVxlMlZP6rg/tux8CQeJ4i/Jcg6ByS2gA+ht2sH85WnWkBN20KHTwlbcNi8kxMS7JSG/SuoVInE0o3DRK4MRwiL0iaK06PQonmDEHPfYhGx722qM2VGjG7Z9HhkVjiOsNDG2gz+XK3ATQT2kzPkU9rvQKyifEvQ+80Oc17ZfzH6lU660br1FtjwIDAQABo1MwUTAdBgNVHQ4EFgQUUmzPHEPvQQx8Uhh+LpbqLFGGzfkwHwYDVR0jBBgwFoAUUmzPHEPvQQx8Uhh+LpbqLFGGzfkwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAToj//ocubvs2cRtarrC1jlsgRjiYQx5v7FoFXK+YNWspgF4I8JaeuuYkACM9bouutDAcZYoigqw5QUJUPimsLuuE2dIoYyHsb+UZGa/R7z5i7UhZfKL+RDCbKuMjx1Now30eh4ZSkKHpo1BsCGZf1cQl4xFEn9kAU9Dt//oZOuhk3GU3wqfXK9Y3RHTPqOhEI/SMeOkOjTteOe95Ic1coLoY+PuOnBkxV+sdX9pXdwD11Drp1k0HCEIhJXPJbGBb2tEKPT9Ww7DCZblh2VtA1/MGXD7us7dum44pjW+agDBdL4z0FVEm6H8ESb5oL5xj4d5L+KSxdogxxJT25BfsOw==";

    @Test
    public void testSaveAndReadCertificate() throws YkPivException, CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        java.security.cert.Certificate cert;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(TEST_CERT_DER))) {
            cert = certificateFactory.generateCertificate(bais);
        }
        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
            ykPiv.saveCertificate(KeySlot.AUTHENTICATION, cert);
            Certificate fetched = ykPiv.readCertificate(KeySlot.AUTHENTICATION);
            Assert.assertArrayEquals(cert.getEncoded(), fetched.getEncoded());
        }
    }

    @Test
    public void testChangePin() throws YkPivException {
        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.verify("111111");
            ykPiv.changePin(YkPiv.DEFAULT_PIN, "222222");
            YkPiv.VerifyResult result = ykPiv.verify(null);
            Assert.assertEquals(3, result.getNumRetries());
        }
        try (YkPiv ykPiv = new YkPiv()) {
            YkPiv.VerifyResult result = ykPiv.verify("222222");
            Assert.assertTrue(result.isVerified());
        }
        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.changePin("222222", YkPiv.DEFAULT_PIN);
        }
        try (YkPiv ykPiv = new YkPiv()) {
            YkPiv.VerifyResult result = ykPiv.verify(YkPiv.DEFAULT_PIN);
            Assert.assertTrue(result.isVerified());
        }
    }

    @Test
    public void testUnblockPin() throws YkPivException {
        // Cause the PIN to get blocked
        try (YkPiv ykPiv = new YkPiv()) {
            for (int i = 0; i < 3; i++) {
                ykPiv.verify("111111");
            }
            YkPiv.VerifyResult result = ykPiv.verify(null);
            Assert.assertFalse(result.isVerified());
            Assert.assertEquals(0, result.getNumRetries());
        }

        try (YkPiv ykPiv = new YkPiv()) {
            YkPiv.VerifyResult result = ykPiv.verify(YkPiv.DEFAULT_PIN);
            Assert.assertFalse(result.isVerified());
        }

        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.unblockPin(YkPiv.DEFAULT_PUK, YkPiv.DEFAULT_PIN);
        }
        try (YkPiv ykPiv = new YkPiv()) {
            YkPiv.VerifyResult result = ykPiv.verify(YkPiv.DEFAULT_PIN);
            Assert.assertTrue(result.isVerified());
        }
    }

    @Test
    public void testChangePuk() throws YkPivException {
        // Cause the PIN to get blocked
        try (YkPiv ykPiv = new YkPiv()) {
            for (int i = 0; i < 3; i++) {
                ykPiv.verify("111111");
            }
        }

        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.changePuk(YkPiv.DEFAULT_PUK, "11111111");
            try {
                ykPiv.unblockPin(YkPiv.DEFAULT_PUK, YkPiv.DEFAULT_PIN);
                Assert.fail("Should have thrown an exception.");
            } catch (YkPivException e) {
                Assert.assertTrue(e.getMessage().startsWith("Wrong PIN"));
            }
            YkPiv.VerifyResult result = ykPiv.verify(YkPiv.DEFAULT_PIN);
            Assert.assertFalse(result.isVerified());

            ykPiv.unblockPin("11111111", YkPiv.DEFAULT_PIN);
            result = ykPiv.verify(YkPiv.DEFAULT_PIN);
            Assert.assertTrue(result.isVerified());

            ykPiv.changePuk("11111111", YkPiv.DEFAULT_PUK);
        }

        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.unblockPin(YkPiv.DEFAULT_PUK, YkPiv.DEFAULT_PIN);
            YkPiv.VerifyResult result = ykPiv.verify(YkPiv.DEFAULT_PIN);
            Assert.assertTrue(result.isVerified());
        }
    }

    @Test
    public void testAttest() throws YkPivException, CertificateEncodingException {
        try (YkPiv ykPiv = new YkPiv()) {
            ykPiv.authencate(YkPiv.DEFAULT_MGMT_KEY);
            ykPiv.verify(YkPiv.DEFAULT_PIN);
            PublicKey publicKey = ykPiv.generateKey(KeySlot.AUTHENTICATION, KeyAlgorithm.RSA_2048, PinPolicy.NEVER, TouchPolicy.NEVER);
            X509Certificate cert = (X509Certificate) ykPiv.attest(KeySlot.AUTHENTICATION);
            Assert.assertEquals("CN=YubiKey PIV Attestation 9a", cert.getSubjectDN().toString());
            Assert.assertEquals(publicKey, cert.getPublicKey());
        }
    }
}