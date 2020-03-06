package lib.org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import lib.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import lib.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import lib.org.bouncycastle.crypto.KeyGenerationParameters;
import lib.org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import lib.org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class X25519KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
