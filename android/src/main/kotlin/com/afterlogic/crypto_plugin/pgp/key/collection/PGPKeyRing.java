
package com.afterlogic.crypto_plugin.pgp.key.collection;




import com.afterlogic.crypto_plugin.pgp.key.OpenPgpV4Fingerprint;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class PGPKeyRing {

    private PGPPublicKeyRing publicKeys;
    private PGPSecretKeyRing secretKeys;

    public PGPKeyRing( PGPPublicKeyRing publicKeys,  PGPSecretKeyRing secretKeys) {

        if (publicKeys.getPublicKey().getKeyID() != secretKeys.getPublicKey().getKeyID()) {
            throw new IllegalArgumentException("publicKeys and secretKeys must have the same master key.");
        }

        this.publicKeys = publicKeys;
        this.secretKeys = secretKeys;
    }

    public PGPKeyRing( PGPPublicKeyRing publicKeys) {
        this.publicKeys = publicKeys;
    }

    public PGPKeyRing( PGPSecretKeyRing secretKeys) {
        this.secretKeys = secretKeys;
    }

    public long getKeyId() {
        return getMasterKey().getKeyID();
    }

    public
    PGPPublicKey getMasterKey() {
        PGPPublicKey publicKey = hasSecretKeys() ? secretKeys.getPublicKey() : publicKeys.getPublicKey();
        if (!publicKey.isMasterKey()) {
            throw new IllegalStateException("Expected master key is not a master key");
        }
        return publicKey;
    }

    public OpenPgpV4Fingerprint getV4Fingerprint() {
        return new OpenPgpV4Fingerprint(getMasterKey());
    }

    public boolean hasSecretKeys() {
        return secretKeys != null;
    }

    public
    PGPPublicKeyRing getPublicKeys() {
        return publicKeys;
    }

    public
    PGPSecretKeyRing getSecretKeys() {
        return secretKeys;
    }
}
