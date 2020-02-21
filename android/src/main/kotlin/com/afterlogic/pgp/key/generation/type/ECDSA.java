
package com.afterlogic.pgp.key.generation.type;




import com.afterlogic.pgp.key.generation.type.curve.EllipticCurve;

import com.afterlogic.pgp.algorithm.PublicKeyAlgorithm;

public class ECDSA extends ECDH {

    ECDSA( EllipticCurve curve) {
        super(curve);
    }

    public static ECDSA fromCurve(EllipticCurve curve) {
        return new ECDSA(curve);
    }

    @Override
    public String getName() {
        return "ECDSA";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ECDSA;
    }
}
