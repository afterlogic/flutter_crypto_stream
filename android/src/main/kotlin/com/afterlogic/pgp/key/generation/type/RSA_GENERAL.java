
package com.afterlogic.pgp.key.generation.type;



import com.afterlogic.pgp.key.generation.type.length.RsaLength;

import com.afterlogic.pgp.algorithm.PublicKeyAlgorithm;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

public class RSA_GENERAL implements KeyType {

    private final RsaLength length;

    RSA_GENERAL( RsaLength length) {
        this.length = length;
    }

    public static RSA_GENERAL withLength(RsaLength length) {
        return new RSA_GENERAL(length);
    }

    @Override
    public String getName() {
        return "RSA";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.RSA_GENERAL;
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new RSAKeyGenParameterSpec(length.getLength(), RSAKeyGenParameterSpec.F4);
    }
}
