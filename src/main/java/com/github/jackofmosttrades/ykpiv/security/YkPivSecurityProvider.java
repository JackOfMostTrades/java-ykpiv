package com.github.jackofmosttrades.ykpiv.security;

import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

/**
 * A JCE security provider which is backed by a yubikey PIV application. Installing this provider allows you to
 * create a KeyManagerFactory which will yield keys representing the private key on a yubikey. It also installs
 * Signature implementations that will sign data using the yubikey.
 *
 * For example:
 *
 *    Security.addProvider(new YkPivSecurityProvider());
 *
 *    SSLContext sslContext = SSLContext.getInstance("TLS");
 *    KeyManagerFactory kmf = KeyManagerFactory.getInstance(YkPivKeyManagerFactory.ALGORITHM);
 *    kmf.init(YkPivKeyManagerFactory.initParameters(KeySlot.AUTHENTICATION));
 *    sslContext.init(kmf.getKeyManagers(), null, null);
 */
public class YkPivSecurityProvider extends Provider {
    public static final String PROVIDER_NAME = "YKPIV";

    public YkPivSecurityProvider() {
        super(PROVIDER_NAME, 1.0, "Security provider backed by yubikey PIV application.");

        final Map<String, String> attrs = new HashMap<>();
        attrs.put("SupportedKeyClasses", YkPivPrivateKey.class.getName());

        putService(new Service(this, "KeyManagerFactory", YkPivKeyManagerFactory.ALGORITHM,
                YkPivKeyManagerFactory.YkPivKeyManagerFactorySpi.class.getName(), null, null));

        putService(new Service(this, "Signature", "MD5withRSA",
                YkPivSignature.MD5withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA1withRSA",
                YkPivSignature.SHA1withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA224withRSA",
                YkPivSignature.SHA224withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA256withRSA",
                YkPivSignature.SHA256withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA384withRSA",
                YkPivSignature.SHA384withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA512withRSA",
                YkPivSignature.SHA512withYKPIV.class.getName(), null, attrs));

        putService(new Service(this, "Signature", "MD5withECDSA",
                YkPivSignature.MD5withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA1withECDSA",
                YkPivSignature.SHA1withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA224withECDSA",
                YkPivSignature.SHA224withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA256withECDSA",
                YkPivSignature.SHA256withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA384withECDSA",
                YkPivSignature.SHA384withYKPIV.class.getName(), null, attrs));
        putService(new Service(this, "Signature", "SHA512withECDSA",
                YkPivSignature.SHA512withYKPIV.class.getName(), null, attrs));
    }
}
