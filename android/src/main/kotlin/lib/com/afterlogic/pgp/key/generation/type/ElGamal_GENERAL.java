
package lib.com.afterlogic.pgp.key.generation.type;



import lib.com.afterlogic.pgp.key.generation.type.length.ElGamalLength;

import lib.org.bouncycastle.jce.spec.ElGamalParameterSpec;
import lib.com.afterlogic.pgp.algorithm.PublicKeyAlgorithm;

import java.security.spec.AlgorithmParameterSpec;

public class ElGamal_GENERAL implements KeyType {

    private final ElGamalLength length;

    ElGamal_GENERAL( ElGamalLength length) {
        this.length = length;
    }

    public static ElGamal_GENERAL withLength(ElGamalLength length) {
        return new ElGamal_GENERAL(length);
    }

    @Override
    public String getName() {
        return "ElGamal";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ELGAMAL_GENERAL;
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ElGamalParameterSpec(length.getP(), length.getG());
    }
}
