package lib.org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;

import lib.org.bouncycastle.crypto.params.DHParameters;
import lib.org.bouncycastle.util.Arrays;
import lib.org.bouncycastle.util.Fingerprint;
import lib.org.bouncycastle.util.Strings;

class JcaJceDhDHUtil
{
    static String privateKeyToString(String algorithm, BigInteger x, DHParameters dhParams)
    {
        StringBuffer buf = new StringBuffer();
        String       nl = Strings.lineSeparator();

        BigInteger y = dhParams.getG().modPow(x, dhParams.getP());

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
        buf.append("              Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    static String publicKeyToString(String algorithm, BigInteger y, DHParameters dhParams)
    {
        StringBuffer buf = new StringBuffer();
        String       nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
        buf.append("             Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    private static String generateKeyFingerprint(BigInteger y, DHParameters dhParams)
    {
            return new Fingerprint(
                Arrays.concatenate(
                    y.toByteArray(),
                    dhParams.getP().toByteArray(), dhParams.getG().toByteArray())).toString();
    }
}
