
package lib.com.afterlogic.pgp.key.selection.keyring.impl;



import lib.com.afterlogic.pgp.key.selection.key.PublicKeySelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.key.SecretKeySelectionStrategy;

import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPSecretKey;

import java.util.Iterator;

public class PartialUserId {

    public static class PubRingSelectionStrategy extends PublicKeySelectionStrategy<String> {

        @Override
        public boolean accept(String identifier,  PGPPublicKey key) {
            for (Iterator<String> userIds = key.getUserIDs(); userIds.hasNext(); ) {
                String userId = userIds.next();
                if (userId.contains(identifier)) {
                    return true;
                }
            }
            return false;
        }
    }

    public static class SecRingSelectionStrategy extends SecretKeySelectionStrategy<String> {

        @Override
        public boolean accept(String identifier,  PGPSecretKey key) {
            for (Iterator<String> userIds = key.getUserIDs(); userIds.hasNext(); ) {
                String userId = userIds.next();
                if (userId.contains(identifier)) {
                    return true;
                }
            }
            return false;
        }
    }
}
