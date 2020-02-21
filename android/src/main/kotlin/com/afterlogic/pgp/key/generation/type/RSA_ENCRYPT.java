
package com.afterlogic.pgp.key.generation.type;



import com.afterlogic.pgp.key.generation.type.length.RsaLength;

import com.afterlogic.pgp.algorithm.PublicKeyAlgorithm;

public class RSA_ENCRYPT extends RSA_GENERAL {

    RSA_ENCRYPT( RsaLength length) {
        super(length);
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.RSA_ENCRYPT;
    }
}
