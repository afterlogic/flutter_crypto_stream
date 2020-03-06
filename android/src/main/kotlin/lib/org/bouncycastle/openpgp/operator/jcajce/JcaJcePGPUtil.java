package lib.org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import lib.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import lib.org.bouncycastle.asn1.x9.ECNamedCurveTable;
import lib.org.bouncycastle.asn1.x9.X9ECParameters;
import lib.org.bouncycastle.crypto.ec.CustomNamedCurves;
import lib.org.bouncycastle.math.ec.ECCurve;
import lib.org.bouncycastle.math.ec.ECPoint;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.util.BigIntegers;

/**
 * Basic utility class
 */
class JcaJcePGPUtil
{
    public static SecretKey makeSymmetricKey(
        int             algorithm,
        byte[]          keyBytes)
        throws PGPException
    {
        String    algName = lib.org.bouncycastle.openpgp.PGPUtil.getSymmetricCipherName(algorithm);

        if (algName == null)
        {
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        return new SecretKeySpec(keyBytes, algName);
    }

    static ECPoint decodePoint(
        BigInteger encodedPoint,
        ECCurve curve)
        throws IOException
    {
        return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
    }

    static X9ECParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
    {
        X9ECParameters x9Params = CustomNamedCurves.getByOID(curveOID);

        if (x9Params == null)
        {
            return ECNamedCurveTable.getByOID(curveOID);
        }

        return x9Params;
    }
}
