
package lib.com.afterlogic.pgp.decryption_verification;



import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import lib.com.afterlogic.pgp.key.OpenPgpV4Fingerprint;
import lib.com.afterlogic.pgp.key.protection.SecretKeyRingProtector;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

public interface DecryptionBuilderInterface {

    DecryptWith onInputStream(InputStream inputStream);

    interface DecryptWith {

        VerifyWith decryptWith( SecretKeyRingProtector decryptor,  PGPSecretKeyRingCollection secretKeyRings);

        VerifyWith doNotDecrypt();

    }

    interface VerifyWith {

        HandleMissingPublicKeys verifyWith( PGPPublicKeyRingCollection publicKeyRings);

        HandleMissingPublicKeys verifyWith( Set<OpenPgpV4Fingerprint> trustedFingerprints,  PGPPublicKeyRingCollection publicKeyRings);

        HandleMissingPublicKeys verifyWith( Set<PGPPublicKeyRing> publicKeyRings);

        Build doNotVerify();

    }

    interface HandleMissingPublicKeys {

        Build handleMissingPublicKeysWith( MissingPublicKeyCallback callback);

        Build ignoreMissingPublicKeys();
    }

    interface Build {

        DecryptionStream build() throws IOException, PGPException;

    }

}
