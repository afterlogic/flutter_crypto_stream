
package lib.com.afterlogic.pgp.key.selection.keyring.impl;

import lib.com.afterlogic.pgp.key.selection.keyring.PublicKeyRingSelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.keyring.SecretKeyRingSelectionStrategy;

import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.util.Iterator;

public class ExactUserId {

    public static class PubRingSelectionStrategy extends PublicKeyRingSelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPPublicKeyRing keyRing) {
            Iterator<String> userIds = keyRing.getPublicKey().getUserIDs();
            while (userIds.hasNext()) {
                if (userIds.next().equals(identifier)) return true;
            }
            return false;
        }
    }

    public static class SecRingSelectionStrategy extends SecretKeyRingSelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPSecretKeyRing keyRing) {
            Iterator<String> userIds = keyRing.getPublicKey().getUserIDs();
            while (userIds.hasNext()) {
                if (userIds.next().equals(identifier)) return true;
            }
            return false;
        }
    }
}
