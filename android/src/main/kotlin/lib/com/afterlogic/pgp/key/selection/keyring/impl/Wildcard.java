
package lib.com.afterlogic.pgp.key.selection.keyring.impl;

import lib.com.afterlogic.pgp.key.selection.keyring.PublicKeyRingSelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.keyring.SecretKeyRingSelectionStrategy;

import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;

public class Wildcard {

    public class PubRingSelectionStrategy<O> extends PublicKeyRingSelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPPublicKeyRing keyRing) {
            return true;
        }
    }

    public class SecRingSelectionStrategy<O> extends SecretKeyRingSelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPSecretKeyRing keyRing) {
            return true;
        }
    }
}
