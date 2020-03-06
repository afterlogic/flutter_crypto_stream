
package lib.com.afterlogic.pgp.key.selection.key.impl;



import lib.com.afterlogic.pgp.key.selection.key.PublicKeySelectionStrategy;

import lib.org.bouncycastle.openpgp.PGPPublicKey;


public class EncryptionKeySelectionStrategy<O> extends PublicKeySelectionStrategy<O> {

    @Override
    public boolean accept(O identifier,  PGPPublicKey key) {
        return key.isEncryptionKey();
    }
}
