package lib.org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import lib.org.bouncycastle.asn1.ASN1Encodable;
import lib.org.bouncycastle.asn1.ASN1OctetString;
import lib.org.bouncycastle.asn1.ASN1Primitive;
import lib.org.bouncycastle.asn1.DERBitString;
import lib.org.bouncycastle.asn1.DEROctetString;
import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import lib.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import lib.org.bouncycastle.asn1.x9.X962Parameters;
import lib.org.bouncycastle.asn1.x9.X9ECPoint;
import lib.org.bouncycastle.asn1.x9.X9IntegerConverter;
import lib.org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import lib.org.bouncycastle.crypto.params.ECDomainParameters;
import lib.org.bouncycastle.crypto.params.ECPublicKeyParameters;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.JcajceUtilECUtil;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.JcajceUtilKeyUtil;
import lib.org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import lib.org.bouncycastle.jce.interfaces.ECPointEncoder;
import lib.org.bouncycastle.jce.provider.BouncyCastleProvider;
import lib.org.bouncycastle.math.ec.ECCurve;

public class BCECPublicKey
    implements ECPublicKey, lib.org.bouncycastle.jce.interfaces.ECPublicKey, ECPointEncoder
{
    static final long serialVersionUID = 2422789860422731812L;

    private String    algorithm = "EC";
    private boolean   withCompression;

    private transient ECPublicKeyParameters   ecPublicKey;
    private transient ECParameterSpec         ecSpec;
    private transient ProviderConfiguration   configuration;

    public BCECPublicKey(
        String algorithm,
        BCECPublicKey key)
    {
        this.algorithm = algorithm;
        this.ecPublicKey = key.ecPublicKey;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.configuration = key.configuration;
    }
    
    public BCECPublicKey(
        String algorithm,
        ECPublicKeySpec spec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.ecSpec = spec.getParams();
        this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(ecSpec, spec.getW(), false), EC5Util.getDomainParameters(configuration, spec.getParams()));
        this.configuration = configuration;
    }

    public BCECPublicKey(
        String algorithm,
        lib.org.bouncycastle.jce.spec.ECPublicKeySpec spec,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;

        if (spec.getParams() != null) // can be null if implictlyCa
        {
            ECCurve curve = spec.getParams().getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

            // this may seem a little long-winded but it's how we pick up the custom curve.
            this.ecPublicKey = new ECPublicKeyParameters(
                spec.getQ(), JcajceUtilECUtil.getDomainParameters(configuration, spec.getParams()));
            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
        }
        else
        {
            lib.org.bouncycastle.jce.spec.ECParameterSpec s = configuration.getEcImplicitlyCa();

            this.ecPublicKey = new ECPublicKeyParameters(s.getCurve().createPoint(spec.getQ().getAffineXCoord().toBigInteger(), spec.getQ().getAffineYCoord().toBigInteger()), EC5Util.getDomainParameters(configuration, (ECParameterSpec)null));
            this.ecSpec = null;
        }

        this.configuration = configuration;
    }
    
    public BCECPublicKey(
        String algorithm,
        ECPublicKeyParameters params,
        ECParameterSpec spec,
        ProviderConfiguration configuration)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;
        this.ecPublicKey = params;

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = createSpec(ellipticCurve, dp);
        }
        else
        {
            this.ecSpec = spec;
        }

        this.configuration = configuration;
    }

    public BCECPublicKey(
        String algorithm,
        ECPublicKeyParameters params,
        lib.org.bouncycastle.jce.spec.ECParameterSpec spec,
        ProviderConfiguration configuration)
    {
        ECDomainParameters      dp = params.getParameters();

        this.algorithm = algorithm;

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = createSpec(ellipticCurve, dp);
        }
        else
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec);
        }

        this.ecPublicKey = params;
        this.configuration = configuration;
    }

    /*
     * called for implicitCA
     */
    public BCECPublicKey(
        String algorithm,
        ECPublicKeyParameters params,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.ecPublicKey = params;
        this.ecSpec = null;
        this.configuration = configuration;
    }

    public BCECPublicKey(
        ECPublicKey key,
        ProviderConfiguration configuration)
    {
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
        this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(this.ecSpec, key.getW(), false), EC5Util.getDomainParameters(configuration, key.getParams()));
    }

    BCECPublicKey(
        String algorithm,
        SubjectPublicKeyInfo info,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.configuration = configuration;
        populateFromPubKeyInfo(info);
    }

    private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp)
    {
        return new ECParameterSpec(
            ellipticCurve,
            EC5Util.convertPoint(dp.getG()),
            dp.getN(),
            dp.getH().intValue());
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
    {
        X962Parameters params = X962Parameters.getInstance(info.getAlgorithm().getParameters());
        ECCurve curve = EC5Util.getCurve(configuration, params);
        ecSpec = EC5Util.convertToSpec(params, curve);

        DERBitString    bits = info.getPublicKeyData();
        byte[]          data = bits.getBytes();
        ASN1OctetString key = new DEROctetString(data);

        //
        // extra octet string - one of our old certs...
        //
        if (data[0] == 0x04 && data[1] == data.length - 2
            && (data[2] == 0x02 || data[2] == 0x03))
        {
            int qLength = new X9IntegerConverter().getByteLength(curve);

            if (qLength >= data.length - 3)
            {
                try
                {
                    key = (ASN1OctetString) ASN1Primitive.fromByteArray(data);
                }
                catch (IOException ex)
                {
                    throw new IllegalArgumentException("error recovering public key");
                }
            }
        }

        X9ECPoint derQ = new X9ECPoint(curve, key);

        this.ecPublicKey = new ECPublicKeyParameters(derQ.getPoint(), JcajceUtilECUtil.getDomainParameters(configuration, params));
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        ASN1Encodable   params = ECUtils.getDomainParametersFromName(ecSpec, withCompression);
        ASN1OctetString p = ASN1OctetString.getInstance(new X9ECPoint(ecPublicKey.getQ(), withCompression).toASN1Primitive());

        // stored curve is null if ImplicitlyCa
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), p.getOctets());

        return JcajceUtilKeyUtil.getEncodedSubjectPublicKeyInfo(info);
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public lib.org.bouncycastle.jce.spec.ECParameterSpec getParameters()
    {
        if (ecSpec == null)     // implictlyCA
        {
            return null;
        }

        return EC5Util.convertSpec(ecSpec, withCompression);
    }

    public ECPoint getW()
    {
        return EC5Util.convertPoint(ecPublicKey.getQ());
    }

    public lib.org.bouncycastle.math.ec.ECPoint getQ()
    {
        lib.org.bouncycastle.math.ec.ECPoint q = ecPublicKey.getQ();

        if (ecSpec == null)
        {
            return q.getDetachedPoint();
        }

        return q;
    }

    ECPublicKeyParameters engineGetKeyParameters()
    {
        return ecPublicKey;
    }

    lib.org.bouncycastle.jce.spec.ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return EC5Util.convertSpec(ecSpec, withCompression);
        }

        return configuration.getEcImplicitlyCa();
    }

    public String toString()
    {
        return JcajceUtilECUtil.publicKeyToString("EC", ecPublicKey.getQ(), engineGetSpec());
    }
    
    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof BCECPublicKey))
        {
            return false;
        }

        BCECPublicKey other = (BCECPublicKey)o;

        return ecPublicKey.getQ().equals(other.ecPublicKey.getQ()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return ecPublicKey.getQ().hashCode() ^ engineGetSpec().hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        this.configuration = BouncyCastleProvider.CONFIGURATION;

        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
