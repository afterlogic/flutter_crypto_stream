package lib.org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import lib.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import lib.org.bouncycastle.asn1.x9.ECNamedCurveTable;
import lib.org.bouncycastle.asn1.x9.X9ECParameters;
import lib.org.bouncycastle.crypto.BlockCipher;
import lib.org.bouncycastle.crypto.BufferedBlockCipher;
import lib.org.bouncycastle.crypto.ec.CustomNamedCurves;
import lib.org.bouncycastle.crypto.io.CryptoIoCipherInputStream;
import lib.org.bouncycastle.crypto.modes.CFBBlockCipher;
import lib.org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher;
import lib.org.bouncycastle.crypto.params.KeyParameter;
import lib.org.bouncycastle.crypto.params.ParametersWithIV;
import lib.org.bouncycastle.math.ec.ECCurve;
import lib.org.bouncycastle.math.ec.ECPoint;
import lib.org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import lib.org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import lib.org.bouncycastle.util.BigIntegers;

class BcUtil
{
    static BufferedBlockCipher createStreamCipher(boolean forEncryption, BlockCipher engine, boolean withIntegrityPacket, byte[] key)
    {
        BufferedBlockCipher c;

        if (withIntegrityPacket)
        {
            c = new BufferedBlockCipher(new CFBBlockCipher(engine, engine.getBlockSize() * 8));
        }
        else
        {
            c = new BufferedBlockCipher(new OpenPGPCFBBlockCipher(engine));
        }

        KeyParameter keyParameter = new KeyParameter(key);

        if (withIntegrityPacket)
        {
            c.init(forEncryption, new ParametersWithIV(keyParameter, new byte[engine.getBlockSize()]));
        }
        else
        {
            c.init(forEncryption, keyParameter);
        }

        return c;
    }

    public static PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, BlockCipher engine, byte[] key)
    {
        final BufferedBlockCipher c = createStreamCipher(false, engine, withIntegrityPacket, key);

        return new PGPDataDecryptor()
        {
            public InputStream getInputStream(InputStream in)
            {
                return new CryptoIoCipherInputStream(in, c);
            }

            public int getBlockSize()
            {
                return c.getBlockSize();
            }

            public PGPDigestCalculator getIntegrityCalculator()
            {
                return new OpenPgpBcSHA1PGPDigestCalculator();
            }
        };
    }

    public static BufferedBlockCipher createSymmetricKeyWrapper(boolean forEncryption, BlockCipher engine, byte[] key, byte[] iv)
    {
        BufferedBlockCipher c = new BufferedBlockCipher(new CFBBlockCipher(engine, engine.getBlockSize() * 8));

        c.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));

        return c;
    }

    static X9ECParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
    {
        X9ECParameters x9 = CustomNamedCurves.getByOID(curveOID);
        if (x9 == null)
        {
            x9 = ECNamedCurveTable.getByOID(curveOID);
        }

        return x9;
    }

    static ECPoint decodePoint(
        BigInteger encodedPoint,
        ECCurve    curve)
        throws IOException
    {
        return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
    }
}
