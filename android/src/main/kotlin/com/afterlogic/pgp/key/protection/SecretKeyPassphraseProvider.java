
package com.afterlogic.pgp.key.protection;


import com.afterlogic.pgp.util.Passphrase;


public interface SecretKeyPassphraseProvider {



    Passphrase getPassphraseFor(Long keyId);
}
