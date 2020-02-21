
package com.afterlogic.crypto_plugin.pgp.key.generation.type;



import com.afterlogic.crypto_plugin.pgp.key.generation.type.length.ElGamalLength;

import com.afterlogic.crypto_plugin.pgp.algorithm.PublicKeyAlgorithm;

public class ElGamal_ENCRYPT extends ElGamal_GENERAL {

    ElGamal_ENCRYPT( ElGamalLength length) {
        super(length);
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ELGAMAL_ENCRYPT;
    }
}
