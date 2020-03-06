
package lib.com.afterlogic.pgp.key.selection.key.impl;



import lib.com.afterlogic.pgp.key.selection.key.SecretKeySelectionStrategy;

import lib.org.bouncycastle.openpgp.PGPSecretKey;


public class SignatureKeySelectionStrategy<O> extends SecretKeySelectionStrategy<O> {

    @Override
    public boolean accept(O identifier,  PGPSecretKey key) {
        return key.isSigningKey();
    }

}
