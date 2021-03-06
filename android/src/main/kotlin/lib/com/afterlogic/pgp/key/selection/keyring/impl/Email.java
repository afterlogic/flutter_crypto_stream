
package lib.com.afterlogic.pgp.key.selection.keyring.impl;



import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPSecretKey;

public class Email {

    public static class PubRingSelectionStrategy extends PartialUserId.PubRingSelectionStrategy {

        @Override
        public boolean accept( String email,  PGPPublicKey key) {
                        if (!email.matches("^<.+>$")) {
                email = "<" + email + ">";
            }
            return super.accept(email, key);
        }
    }

    public static class SecRingSelectionStrategy extends PartialUserId.SecRingSelectionStrategy {

        @Override
        public boolean accept(String email, PGPSecretKey key) {
                        if (!email.matches("^<.+>$")) {
                email = "<" + email + ">";
            }
            return super.accept(email, key);
        }
    }
}
