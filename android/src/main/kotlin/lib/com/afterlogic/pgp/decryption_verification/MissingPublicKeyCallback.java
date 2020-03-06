
package lib.com.afterlogic.pgp.decryption_verification;



import lib.org.bouncycastle.openpgp.PGPPublicKey;

public interface MissingPublicKeyCallback {


    PGPPublicKey onMissingPublicKeyEncountered( Long keyId);

}
