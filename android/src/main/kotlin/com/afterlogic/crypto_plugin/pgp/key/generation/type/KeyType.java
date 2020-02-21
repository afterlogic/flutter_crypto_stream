
package com.afterlogic.crypto_plugin.pgp.key.generation.type;

import com.afterlogic.crypto_plugin.pgp.algorithm.PublicKeyAlgorithm;

import java.security.spec.AlgorithmParameterSpec;

public interface KeyType {

    String getName();

    PublicKeyAlgorithm getAlgorithm();

    AlgorithmParameterSpec getAlgorithmSpec();
}
