
package lib.com.afterlogic.pgp.key.selection.keyring.impl;

import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;

public class XMPP {

    public static class PubRingSelectionStrategy extends ExactUserId.PubRingSelectionStrategy {

        @Override
        public boolean accept(String jid, PGPPublicKeyRing keyRing) {
            return super.accept("xmpp:" + jid, keyRing);
        }
    }

    public static class SecRingSelectionStrategy extends ExactUserId.SecRingSelectionStrategy {

        @Override
        public boolean accept(String jid, PGPSecretKeyRing keyRing) {
            return super.accept("xmpp:" + jid, keyRing);
        }
    }
}
