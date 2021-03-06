package lib.org.bouncycastle.jcajce.provider.asymmetric.ecgost;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import lib.org.bouncycastle.asn1.x9.X9IntegerConverter;
import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.crypto.DerivationFunction;
import lib.org.bouncycastle.crypto.agreement.ECVKOAgreement;
import lib.org.bouncycastle.crypto.digests.GOST3411Digest;
import lib.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import lib.org.bouncycastle.crypto.params.ECDomainParameters;
import lib.org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import lib.org.bouncycastle.crypto.params.ParametersWithUKM;
import lib.org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.JcajceUtilECUtil;
import lib.org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import lib.org.bouncycastle.jce.interfaces.JceECPrivateKey;
import lib.org.bouncycastle.jce.interfaces.ECPublicKey;

public class JcajceEcgostKeyAgreementSpi
    extends BaseAgreementSpi
{
    private static final X9IntegerConverter converter = new X9IntegerConverter();

    private String                 kaAlgorithm;

    private ECDomainParameters     parameters;
    private ECVKOAgreement agreement;

    private byte[]             result;

    protected JcajceEcgostKeyAgreementSpi(
        String kaAlgorithm,
        ECVKOAgreement agreement,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);

        this.kaAlgorithm = kaAlgorithm;
        this.agreement = agreement;
    }

    protected Key engineDoPhase(
        Key     key,
        boolean lastPhase) 
        throws InvalidKeyException, IllegalStateException
    {
        if (parameters == null)
        {
            throw new IllegalStateException(kaAlgorithm + " not initialised.");
        }

        if (!lastPhase)
        {
            throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
        }

        CipherParameters pubKey;
        {
            if (!(key instanceof PublicKey))
            {
                throw new InvalidKeyException(kaAlgorithm + " key agreement requires "
                    + getSimpleName(ECPublicKey.class) + " for doPhase");
            }

            pubKey = generatePublicKeyParameter((PublicKey)key);
        }

        try
        {
            result = agreement.calculateAgreement(pubKey);
        }
        catch (final Exception e)
        {
            throw new InvalidKeyException("calculation failed: " + e.getMessage())
            {
                public Throwable getCause()
                            {
                                return e;
                            }
            };
        }

        return null;
    }

    protected void engineInit(
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random) 
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null && !(params instanceof UserKeyingMaterialSpec))
        {
            throw new InvalidAlgorithmParameterException("No algorithm parameters supported");
        }

        initFromKey(key, params);
    }

    protected void engineInit(
        Key             key,
        SecureRandom    random) 
        throws InvalidKeyException
    {
        initFromKey(key, null);
    }

    private void initFromKey(Key key, AlgorithmParameterSpec parameterSpec)
        throws InvalidKeyException
    {
        {
            if (!(key instanceof PrivateKey))
            {
                throw new InvalidKeyException(kaAlgorithm + " key agreement requires "
                    + getSimpleName(JceECPrivateKey.class) + " for initialisation");
            }

            ECPrivateKeyParameters privKey = (ECPrivateKeyParameters) JcajceUtilECUtil.generatePrivateKeyParameter((PrivateKey)key);
            this.parameters = privKey.getParameters();
            ukmParameters = (parameterSpec instanceof UserKeyingMaterialSpec) ? ((UserKeyingMaterialSpec)parameterSpec).getUserKeyingMaterial() : null;
            agreement.init(new ParametersWithUKM(privKey, ukmParameters));
        }
    }

    private static String getSimpleName(Class clazz)
    {
        String fullName = clazz.getName();

        return fullName.substring(fullName.lastIndexOf('.') + 1);
    }

    protected byte[] calcSecret()
    {
        return result;
    }

    static AsymmetricKeyParameter generatePublicKeyParameter(
            PublicKey key)
        throws InvalidKeyException
    {
        return (key instanceof BCECPublicKey) ? ((BCECGOST3410PublicKey)key).engineGetKeyParameters() : JcajceUtilECUtil.generatePublicKeyParameter(key);
    }

    public static class ECVKO
        extends JcajceEcgostKeyAgreementSpi
    {
        public ECVKO()
        {
            super("ECGOST3410", new ECVKOAgreement(new GOST3411Digest()), null);
        }
    }
}
