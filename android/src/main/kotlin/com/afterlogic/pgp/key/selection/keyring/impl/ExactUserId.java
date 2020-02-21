
package com.afterlogic.pgp.key.selection.keyring.impl;

import com.afterlogic.pgp.key.selection.keyring.PublicKeyRingSelectionStrategy;
import com.afterlogic.pgp.key.selection.keyring.SecretKeyRingSelectionStrategy;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

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
