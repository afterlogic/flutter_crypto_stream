
package lib.com.afterlogic.pgp.decryption_verification;


import lib.com.afterlogic.pgp.key.protection.SecretKeyRingProtector;

import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import lib.com.afterlogic.pgp.key.OpenPgpV4Fingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class DecryptionBuilder implements DecryptionBuilderInterface {

    private InputStream inputStream;
    private PGPSecretKeyRingCollection decryptionKeys;
    private SecretKeyRingProtector decryptionKeyDecryptor;
    private Set<PGPPublicKeyRing> verificationKeys = new HashSet<>();
    private MissingPublicKeyCallback missingPublicKeyCallback = null;

    @Override
    public DecryptWith onInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
        return new DecryptWithImpl();
    }

    class DecryptWithImpl implements DecryptWith {

        @Override
        public VerifyWith decryptWith(SecretKeyRingProtector decryptor, PGPSecretKeyRingCollection secretKeyRings) {
            DecryptionBuilder.this.decryptionKeys = secretKeyRings;
            DecryptionBuilder.this.decryptionKeyDecryptor = decryptor;
            return new VerifyWithImpl();
        }

        @Override
        public VerifyWith doNotDecrypt() {
            DecryptionBuilder.this.decryptionKeys = null;
            DecryptionBuilder.this.decryptionKeyDecryptor = null;
            return new VerifyWithImpl();
        }
    }

    class VerifyWithImpl implements VerifyWith {

        @Override
        public HandleMissingPublicKeys verifyWith(PGPPublicKeyRingCollection publicKeyRingCollection) {
            Set<PGPPublicKeyRing> publicKeyRings = new HashSet<>();
            for (Iterator<PGPPublicKeyRing> i = publicKeyRingCollection.getKeyRings(); i.hasNext(); ) {
                publicKeyRings.add(i.next());
            }
            return verifyWith(publicKeyRings);
        }

        @Override
        public HandleMissingPublicKeys verifyWith(Set<OpenPgpV4Fingerprint> trustedKeyIds,
                                                  PGPPublicKeyRingCollection publicKeyRingCollection) {
            Set<PGPPublicKeyRing> publicKeyRings = new HashSet<>();
            for (Iterator<PGPPublicKeyRing> i = publicKeyRingCollection.getKeyRings(); i.hasNext(); ) {
                PGPPublicKeyRing p = i.next();
                OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(p);
                if (trustedKeyIds.contains(fingerprint)) {
                    publicKeyRings.add(p);
                }
            }
            return verifyWith(publicKeyRings);
        }

        @Override
        public HandleMissingPublicKeys verifyWith(Set<PGPPublicKeyRing> publicKeyRings) {
            DecryptionBuilder.this.verificationKeys = publicKeyRings;
            return new HandleMissingPublicKeysImpl();
        }

        @Override
        public Build doNotVerify() {
            DecryptionBuilder.this.verificationKeys = null;
            return new BuildImpl();
        }
    }

    class HandleMissingPublicKeysImpl implements HandleMissingPublicKeys {

        @Override
        public Build handleMissingPublicKeysWith(MissingPublicKeyCallback callback) {
            DecryptionBuilder.this.missingPublicKeyCallback = callback;
            return new BuildImpl();
        }

        @Override
        public Build ignoreMissingPublicKeys() {
            DecryptionBuilder.this.missingPublicKeyCallback = null;
            return new BuildImpl();
        }
    }

    class BuildImpl implements Build {

        @Override
        public DecryptionStream build() throws IOException, PGPException {
            return DecryptionStreamFactory.create(inputStream,
                    decryptionKeys, decryptionKeyDecryptor, verificationKeys, missingPublicKeyCallback);
        }
    }
}
