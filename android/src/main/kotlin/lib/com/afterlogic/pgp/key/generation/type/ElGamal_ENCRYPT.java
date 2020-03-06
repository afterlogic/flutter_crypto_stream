
package lib.com.afterlogic.pgp.key.generation.type;



import lib.com.afterlogic.pgp.key.generation.type.length.ElGamalLength;

import lib.com.afterlogic.pgp.algorithm.PublicKeyAlgorithm;

public class ElGamal_ENCRYPT extends ElGamal_GENERAL {

    ElGamal_ENCRYPT( ElGamalLength length) {
        super(length);
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ELGAMAL_ENCRYPT;
    }
}
