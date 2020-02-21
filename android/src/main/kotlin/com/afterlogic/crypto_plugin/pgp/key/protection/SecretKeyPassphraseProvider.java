
package com.afterlogic.crypto_plugin.pgp.key.protection;


import com.afterlogic.crypto_plugin.pgp.util.Passphrase;


public interface SecretKeyPassphraseProvider {



    Passphrase getPassphraseFor(Long keyId);
}
