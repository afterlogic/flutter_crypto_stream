package lib.org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import lib.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import lib.org.bouncycastle.crypto.CryptoServicesRegistrar;
import lib.org.bouncycastle.crypto.generators.CryptoRSAKeyPairGenerator;
import lib.org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import lib.org.bouncycastle.crypto.params.RSAKeyParameters;
import lib.org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

public class JcajceRsaKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    public JcajceRsaKeyPairGeneratorSpi(
        String algorithmName)
    {
        super(algorithmName);
    }

    final static BigInteger defaultPublicExponent = BigInteger.valueOf(0x10001);

    RSAKeyGenerationParameters param;
    CryptoRSAKeyPairGenerator engine;

    public JcajceRsaKeyPairGeneratorSpi()
    {
        super("RSA");

        engine = new CryptoRSAKeyPairGenerator();
        param = new RSAKeyGenerationParameters(defaultPublicExponent,
            CryptoServicesRegistrar.getSecureRandom(), 2048, PrimeCertaintyCalculator.getDefaultCertainty(2048));
        engine.init(param);
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        param = new RSAKeyGenerationParameters(defaultPublicExponent,
            random, strength, PrimeCertaintyCalculator.getDefaultCertainty(strength));

        engine.init(param);
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof RSAKeyGenParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec");
        }
        RSAKeyGenParameterSpec rsaParams = (RSAKeyGenParameterSpec)params;

        param = new RSAKeyGenerationParameters(
            rsaParams.getPublicExponent(),
            random, rsaParams.getKeysize(), PrimeCertaintyCalculator.getDefaultCertainty(2048));

        engine.init(param);
    }

    public KeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        RSAKeyParameters pub = (RSAKeyParameters)pair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)pair.getPrivate();

        return new KeyPair(new BCRSAPublicKey(pub),
            new BCRSAPrivateCrtKey(priv));
    }
}
