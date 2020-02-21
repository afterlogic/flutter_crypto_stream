
package com.afterlogic.pgp.key.selection.key.impl;



import com.afterlogic.pgp.key.selection.key.SecretKeySelectionStrategy;

import org.bouncycastle.openpgp.PGPSecretKey;


public class SignatureKeySelectionStrategy<O> extends SecretKeySelectionStrategy<O> {

    @Override
    public boolean accept(O identifier,  PGPSecretKey key) {
        return key.isSigningKey();
    }

}
