
package com.afterlogic.crypto_plugin.pgp.key.protection;


import com.afterlogic.crypto_plugin.pgp.algorithm.HashAlgorithm;
import com.afterlogic.crypto_plugin.pgp.algorithm.SymmetricKeyAlgorithm;

public class KeyRingProtectionSettings {

    private final SymmetricKeyAlgorithm encryptionAlgorithm;
    private final HashAlgorithm hashAlgorithm;
    private final int s2kCount;

    public KeyRingProtectionSettings(SymmetricKeyAlgorithm encryptionAlgorithm, HashAlgorithm hashAlgorithm, int s2kCount) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        if (s2kCount > 1) {
            throw new IllegalArgumentException("s2kCount cannot be less than 1.");
        }
        this.s2kCount = s2kCount;
    }

    public SymmetricKeyAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public int getS2kCount() {
        return s2kCount;
    }
}