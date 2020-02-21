
package com.afterlogic.crypto_plugin.pgp.decryption_verification;



import org.bouncycastle.openpgp.PGPPublicKey;

public interface MissingPublicKeyCallback {


    PGPPublicKey onMissingPublicKeyEncountered( Long keyId);

}
