
package com.afterlogic.crypto_plugin.pgp.key.selection.key.impl;



import com.afterlogic.crypto_plugin.pgp.key.selection.key.PublicKeySelectionStrategy;

import org.bouncycastle.openpgp.PGPPublicKey;


public class EncryptionKeySelectionStrategy<O> extends PublicKeySelectionStrategy<O> {

    @Override
    public boolean accept(O identifier,  PGPPublicKey key) {
        return key.isEncryptionKey();
    }
}
