package lib.org.bouncycastle.jcajce.provider.symmetric;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;

import lib.org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.crypto.PasswordConverter;
import lib.org.bouncycastle.crypto.generators.SCrypt;
import lib.org.bouncycastle.crypto.params.KeyParameter;
import lib.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import lib.org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import lib.org.bouncycastle.jcajce.spec.ScryptKeySpec;

public class JcajceSCRYPT
{
    private JcajceSCRYPT()
    {

    }

    public static class BasePBKDF2
        extends BaseSecretKeyFactory
    {
        private int scheme;

        public BasePBKDF2(String name, int scheme)
        {
            super(name, MiscObjectIdentifiers.id_scrypt);

            this.scheme = scheme;
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof ScryptKeySpec)
            {
                ScryptKeySpec pbeSpec = (ScryptKeySpec)keySpec;

                if (pbeSpec.getSalt() == null)
                {
                    throw new IllegalArgumentException("Salt S must be provided.");
                }
                if (pbeSpec.getCostParameter() <= 1)
                {
                    throw new IllegalArgumentException("Cost parameter N must be > 1.");
                }

                if (pbeSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("positive key length required: "
                        + pbeSpec.getKeyLength());
                }

                if (pbeSpec.getPassword().length == 0)
                {
                    throw new IllegalArgumentException("password empty");
                }

                CipherParameters param = new KeyParameter(SCrypt.generate(
                        PasswordConverter.UTF8.convert(pbeSpec.getPassword()), pbeSpec.getSalt(),
                        pbeSpec.getCostParameter(), pbeSpec.getBlockSize(), pbeSpec.getParallelizationParameter(),
                        pbeSpec.getKeyLength() / 8));

                return new BCPBEKey(this.algName, pbeSpec, param);
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    public static class ScryptWithUTF8
        extends BasePBKDF2
    {
        public ScryptWithUTF8()
        {
            super("SCRYPT", PKCS5S2_UTF8);
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = JcajceSCRYPT.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecretKeyFactory.SCRYPT", PREFIX + "$ScryptWithUTF8");
            provider.addAlgorithm("SecretKeyFactory", MiscObjectIdentifiers.id_scrypt, PREFIX + "$ScryptWithUTF8");
        }
    }
}
