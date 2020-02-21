
package com.afterlogic.pgp.key.protection;




import com.afterlogic.pgp.util.Passphrase;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

import java.util.HashMap;
import java.util.Map;


public class PassphraseMapKeyRingProtector implements SecretKeyRingProtector, SecretKeyPassphraseProvider {

    private final Map<Long, Passphrase> cache = new HashMap<>();
    private final SecretKeyRingProtector protector;
    private final SecretKeyPassphraseProvider provider;

    public PassphraseMapKeyRingProtector( Map<Long, Passphrase> passphrases,
                                          KeyRingProtectionSettings protectionSettings,
                                          SecretKeyPassphraseProvider missingPassphraseCallback) {
        this.cache.putAll(passphrases);
        this.protector = new PasswordBasedSecretKeyRingProtector(protectionSettings, this);
        this.provider = missingPassphraseCallback;
    }


    public void addPassphrase( Long keyId,  Passphrase passphrase) {
        this.cache.put(keyId, passphrase);
    }


    public void forgetPassphrase( Long keyId) {
        Passphrase passphrase = cache.get(keyId);
        passphrase.clear();
        cache.remove(keyId);
    }

    @Override

    public Passphrase getPassphraseFor(Long keyId) {
        Passphrase passphrase = cache.get(keyId);
        if (passphrase == null || !passphrase.isValid()) {
            passphrase = provider.getPassphraseFor(keyId);
            if (passphrase != null) {
                cache.put(keyId, passphrase);
            }
        }
        return passphrase;
    }

    @Override

    public PBESecretKeyDecryptor getDecryptor( Long keyId) {
        return protector.getDecryptor(keyId);
    }

    @Override

    public PBESecretKeyEncryptor getEncryptor( Long keyId) throws PGPException {
        return protector.getEncryptor(keyId);
    }
}
