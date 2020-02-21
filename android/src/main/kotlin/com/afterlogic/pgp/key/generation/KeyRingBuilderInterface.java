
package com.afterlogic.pgp.key.generation;



import com.afterlogic.pgp.key.collection.PGPKeyRing;
import com.afterlogic.pgp.util.Passphrase;

import org.bouncycastle.openpgp.PGPException;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public interface KeyRingBuilderInterface {

    KeyRingBuilderInterface withSubKey(KeySpec keySpec);

    WithPrimaryUserId withMasterKey(KeySpec keySpec);

    interface WithPrimaryUserId {

        WithPassphrase withPrimaryUserId(String userId);

        WithPassphrase withPrimaryUserId(byte[] userId);

    }

    interface WithPassphrase {

        Build withPassphrase(Passphrase passphrase);

        Build withoutPassphrase();
    }

    interface Build {

        PGPKeyRing build() throws NoSuchAlgorithmException, PGPException,
                InvalidAlgorithmParameterException;

    }
}
