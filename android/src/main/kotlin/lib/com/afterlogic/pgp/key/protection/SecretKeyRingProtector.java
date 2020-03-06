
package lib.com.afterlogic.pgp.key.protection;


import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import lib.org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public interface SecretKeyRingProtector {


    PBESecretKeyDecryptor getDecryptor(Long keyId);


    PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException;

}
