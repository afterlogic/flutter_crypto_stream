
package com.afterlogic.pgp.key.protection;


import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public interface SecretKeyRingProtector {


    PBESecretKeyDecryptor getDecryptor(Long keyId);


    PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException;

}
