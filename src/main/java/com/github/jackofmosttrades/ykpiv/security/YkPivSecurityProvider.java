package com.github.jackofmosttrades.ykpiv.security;

import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

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
