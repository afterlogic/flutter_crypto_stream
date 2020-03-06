
package lib.com.afterlogic.pgp.key.generation.type;



import lib.com.afterlogic.pgp.key.generation.type.curve.EllipticCurve;

import lib.org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import lib.com.afterlogic.pgp.algorithm.PublicKeyAlgorithm;

import java.security.spec.AlgorithmParameterSpec;

public class ECDH implements KeyType {

    private final EllipticCurve curve;

    ECDH(EllipticCurve curve) {
        this.curve = curve;
    }

    public static ECDH fromCurve(EllipticCurve curve) {
        return new ECDH(curve);
    }

    @Override
    public String getName() {
        return "ECDH";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ECDH;
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ECNamedCurveGenParameterSpec(curve.getName());
    }
}
