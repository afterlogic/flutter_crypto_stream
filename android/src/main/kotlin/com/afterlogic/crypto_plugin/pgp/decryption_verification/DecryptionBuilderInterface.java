
package com.afterlogic.crypto_plugin.pgp.decryption_verification;



import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import com.afterlogic.crypto_plugin.pgp.key.OpenPgpV4Fingerprint;
import com.afterlogic.crypto_plugin.pgp.key.protection.SecretKeyRingProtector;

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
