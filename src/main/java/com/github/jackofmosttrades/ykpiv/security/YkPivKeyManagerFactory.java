package com.github.jackofmosttrades.ykpiv.security;

import com.github.jackofmosttrades.ykpiv.KeyAlgorithm;
import com.github.jackofmosttrades.ykpiv.KeySlot;
import com.github.jackofmosttrades.ykpiv.YkPiv;
import com.github.jackofmosttrades.ykpiv.YkPivException;

import javax.net.ssl.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * A KeyManagerFactory implementation that yields YkPivPrivateKey instances, i.e. private keys representing keys stored
 * on a yubikey.
 *
 * This class can either be constructed directly, i.e. with
 *     KeyManagerFactory kmf = new YkPivKeyManagerFactory();
 *
 * or by the regular JCE mechanism:
 *     KeyManagerFactory kmf = KeyManagerFactory.getInstance(YkPivKeyManagerFactory.ALGORITHM);
 */
public class YkPivKeyManagerFactory extends KeyManagerFactory {

    public static final String ALGORITHM = "YKPIV";

    public YkPivKeyManagerFactory() {
        super(new YkPivKeyManagerFactorySpi(), null, "YKPIV");
    }

    public static class YkPivKeyManagerFactorySpi extends KeyManagerFactorySpi {

        private YkPivManagerFactoryParameters params = null;

        @Override
        protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
            throw new UnsupportedOperationException("This key manager factory must be init with the ManagerFactoryParameters method.");
        }

        @Override
        protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
            if (!(spec instanceof YkPivManagerFactoryParameters)) {
                throw new IllegalArgumentException("Can only be initialized with parameters returned from YkPivManagerFactory.initParameters(...)");
            }
            this.params = (YkPivManagerFactoryParameters)spec;
        }

        @Override
        protected KeyManager[] engineGetKeyManagers() {
            if (params == null) {
                throw new IllegalStateException("YkPivKeyManagerFactorySpi is not initialized");
            }
            return new KeyManager[] { new YkPivX509ExtendedKeyManager(params) };
        }
    }

    private static class YkPivX509ExtendedKeyManager extends X509ExtendedKeyManager {

        private final YkPiv ykPiv;
        private final KeySlot keySlot;
        private final X509Certificate[] certChain;
        private final YkPivPrivateKey privateKey;

        private YkPivX509ExtendedKeyManager(YkPivManagerFactoryParameters params) {
            try {
                this.ykPiv = new YkPiv();
            } catch (YkPivException e) {
                throw new IllegalStateException("Unable to establish connection to yubikey", e);
            }
            this.keySlot = params.keySlot;

            // Get the cert from this keyslot. We may use params to define the cert chain, but
            // either way we extract the key type from the public key of the cert.
            X509Certificate cert;
            try {
                cert = ykPiv.readCertificate(keySlot);
            } catch (YkPivException e) {
                throw new IllegalStateException("Unable to read certificate from ykpiv", e);
            }

            if (params.certChain == null) {
                certChain = new X509Certificate[] { cert };
            } else {
                this.certChain = params.certChain;
            }

            this.privateKey = new YkPivPrivateKey(ykPiv, deriveKeyAlgorithm(cert.getPublicKey()), keySlot);
        }

        private static KeyAlgorithm deriveKeyAlgorithm(PublicKey publicKey) {
            if (publicKey instanceof RSAPublicKey) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                int keyLength = rsaPublicKey.getModulus().bitLength();
                switch (keyLength) {
                    case 1024:
                        return KeyAlgorithm.RSA_1024;
                    case 2048:
                        return KeyAlgorithm.RSA_2048;
                }
                throw new IllegalStateException("Unsupported RSA key length: " + keyLength);
            }
            if (publicKey instanceof ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                int keyLength = ecPublicKey.getParams().getCurve().getField().getFieldSize();
                switch (keyLength) {
                    case 256:
                        return KeyAlgorithm.EC_256;
                    case 384:
                        return KeyAlgorithm.EC_384;
                }
                throw new IllegalStateException("Unsupported EC key length: " + keyLength);
            }
            throw new IllegalArgumentException("Unsupported public key type: " + publicKey.getClass().getName());
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] { "1" };
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return "1";
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[] { "1" };
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return "1";
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return certChain;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return privateKey;
        }

        @Override
        protected void finalize() throws Throwable {
            ykPiv.close();
            super.finalize();
        }
    }

    private static class YkPivManagerFactoryParameters implements ManagerFactoryParameters {
        private final KeySlot keySlot;
        private final X509Certificate[] certChain;

        private YkPivManagerFactoryParameters(KeySlot keySlot, X509Certificate[] certChain) {
            this.keySlot = keySlot;
            this.certChain = certChain;
        }
    }

    public static ManagerFactoryParameters initParameters(KeySlot keySlot) {
        return initParameters(keySlot, null);
    }

    public static ManagerFactoryParameters initParameters(KeySlot keySlot, X509Certificate[] chain) {
        return new YkPivManagerFactoryParameters(keySlot, chain);
    }
}
