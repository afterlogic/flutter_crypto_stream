package lib.org.bouncycastle.jcajce.provider.symmetric;

import lib.org.bouncycastle.crypto.BlockCipher;
import lib.org.bouncycastle.crypto.CipherKeyGenerator;
import lib.org.bouncycastle.crypto.engines.CAST6Engine;
import lib.org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import lib.org.bouncycastle.crypto.macs.GMac;
import lib.org.bouncycastle.crypto.modes.GCMBlockCipher;
import lib.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import lib.org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class CAST6
{
    private CAST6()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new CAST6Engine();
                }
            });
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("CAST6", 256, new CipherKeyGenerator());
        }
    }

    public static class GMAC
        extends BaseMac
    {
        public GMAC()
        {
            super(new GMac(new GCMBlockCipher(new CAST6Engine())));
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new lib.org.bouncycastle.crypto.macs.Poly1305(new CAST6Engine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-CAST6", 256, new Poly1305KeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "CAST6 IV";
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = CAST6.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.CAST6", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.CAST6", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.CAST6", PREFIX + "$AlgParams");
            
            addGMacAlgorithm(provider, "CAST6", PREFIX + "$GMAC", PREFIX + "$KeyGen");
            addPoly1305Algorithm(provider, "CAST6", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
        }
    }
}