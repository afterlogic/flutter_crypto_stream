
package lib.com.afterlogic.pgp.key.selection.keyring.impl;

import lib.com.afterlogic.pgp.key.selection.keyring.PublicKeyRingSelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.keyring.SecretKeyRingSelectionStrategy;
import lib.com.afterlogic.pgp.util.MultiMap;

import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.util.Map;
import java.util.Set;

public class Whitelist {

    public static class PubRingSelectionStrategy<O> extends PublicKeyRingSelectionStrategy<O> {

        private final MultiMap<O, Long> whitelist;

        public PubRingSelectionStrategy(MultiMap<O, Long> whitelist) {
            this.whitelist = whitelist;
        }

        public PubRingSelectionStrategy(Map<O, Set<Long>> whitelist) {
            this.whitelist = new MultiMap<>(whitelist);
        }

        @Override
        public boolean accept(O identifier, PGPPublicKeyRing keyRing) {
            Set<Long> whitelistedKeyIds = whitelist.get(identifier);

            if (whitelistedKeyIds == null) {
                return false;
            }

            return whitelistedKeyIds.contains(keyRing.getPublicKey().getKeyID());
        }
    }

    public static class SecRingSelectionStrategy<O> extends SecretKeyRingSelectionStrategy<O> {

        private final MultiMap<O, Long> whitelist;

        public SecRingSelectionStrategy(MultiMap<O, Long> whitelist) {
            this.whitelist = whitelist;
        }

        public SecRingSelectionStrategy(Map<O, Set<Long>> whitelist) {
            this.whitelist = new MultiMap<>(whitelist);
        }

        @Override
        public boolean accept(O identifier, PGPSecretKeyRing keyRing) {
            Set<Long> whitelistedKeyIds = whitelist.get(identifier);

            if (whitelistedKeyIds == null) {
                return false;
            }

            return whitelistedKeyIds.contains(keyRing.getPublicKey().getKeyID());
        }

    }
}
