package lib.org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import lib.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import lib.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import lib.org.bouncycastle.crypto.KeyGenerationParameters;
import lib.org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import lib.org.bouncycastle.crypto.params.X448PublicKeyParameters;

public class X448KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        X448PrivateKeyParameters privateKey = new X448PrivateKeyParameters(random);
        X448PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
