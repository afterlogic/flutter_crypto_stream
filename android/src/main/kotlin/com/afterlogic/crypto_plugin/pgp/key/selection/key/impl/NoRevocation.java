
package com.afterlogic.crypto_plugin.pgp.key.selection.key.impl;



import com.afterlogic.crypto_plugin.pgp.key.selection.key.PublicKeySelectionStrategy;
import com.afterlogic.crypto_plugin.pgp.key.selection.key.SecretKeySelectionStrategy;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;


public class NoRevocation {


    public static class PubKeySelectionStrategy<O> extends PublicKeySelectionStrategy<O> {

        @Override
        public boolean accept(O identifier,  PGPPublicKey key) {
            return !key.hasRevocation();
        }
    }


    public static class SecKeySelectionStrategy<O> extends SecretKeySelectionStrategy<O> {

        @Override
        public boolean accept(O identifier,  PGPSecretKey key) {
            return !key.getPublicKey().hasRevocation();
        }
    }
}
