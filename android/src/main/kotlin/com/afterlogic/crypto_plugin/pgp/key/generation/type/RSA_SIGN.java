
package com.afterlogic.crypto_plugin.pgp.key.generation.type;



import com.afterlogic.crypto_plugin.pgp.key.generation.type.length.RsaLength;

import com.afterlogic.crypto_plugin.pgp.algorithm.PublicKeyAlgorithm;

public class RSA_SIGN extends RSA_GENERAL {

    RSA_SIGN( RsaLength length) {
        super(length);
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.RSA_SIGN;
    }
}
