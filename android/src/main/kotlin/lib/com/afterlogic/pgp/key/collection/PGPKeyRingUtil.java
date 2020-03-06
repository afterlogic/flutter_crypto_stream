
package lib.com.afterlogic.pgp.key.collection;




import lib.com.afterlogic.pgp.key.OpenPgpV4Fingerprint;

import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;

public class PGPKeyRingUtil {

    private PGPPublicKeyRing publicKeys;
    private PGPSecretKeyRing secretKeys;

    public PGPKeyRingUtil(PGPPublicKeyRing publicKeys, PGPSecretKeyRing secretKeys) {

        if (publicKeys.getPublicKey().getKeyID() != secretKeys.getPublicKey().getKeyID()) {
            throw new IllegalArgumentException("publicKeys and secretKeys must have the same master key.");
        }

        this.publicKeys = publicKeys;
        this.secretKeys = secretKeys;
    }

    public PGPKeyRingUtil(PGPPublicKeyRing publicKeys) {
        this.publicKeys = publicKeys;
    }

    public PGPKeyRingUtil(PGPSecretKeyRing secretKeys) {
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
