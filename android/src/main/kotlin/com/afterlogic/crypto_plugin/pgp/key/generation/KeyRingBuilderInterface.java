
package com.afterlogic.crypto_plugin.pgp.key.generation;



import com.afterlogic.crypto_plugin.pgp.key.collection.PGPKeyRing;
import com.afterlogic.crypto_plugin.pgp.util.Passphrase;

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
