
package lib.com.afterlogic.pgp.key.generation.type;




import lib.com.afterlogic.pgp.key.generation.type.curve.EllipticCurve;

import lib.com.afterlogic.pgp.algorithm.PublicKeyAlgorithm;

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
