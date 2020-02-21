
package com.afterlogic.pgp.key.generation.type;

import com.afterlogic.pgp.algorithm.PublicKeyAlgorithm;

import java.security.spec.AlgorithmParameterSpec;

public interface KeyType {

    String getName();

    PublicKeyAlgorithm getAlgorithm();

    AlgorithmParameterSpec getAlgorithmSpec();
}
