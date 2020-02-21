
package com.afterlogic.pgp.key.protection;



import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;


public class UnprotectedKeysProtector implements SecretKeyRingProtector {

    @Override

    public PBESecretKeyDecryptor getDecryptor(Long keyId) {
        return null;
    }

    @Override

    public PBESecretKeyEncryptor getEncryptor(Long keyId) {
        return null;
    }
}
