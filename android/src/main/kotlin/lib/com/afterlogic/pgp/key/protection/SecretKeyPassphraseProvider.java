
package lib.com.afterlogic.pgp.key.protection;


import lib.com.afterlogic.pgp.util.Passphrase;


public interface SecretKeyPassphraseProvider {



    Passphrase getPassphraseFor(Long keyId);
}
