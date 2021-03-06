package lib.org.bouncycastle.jce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Enumeration;

import lib.org.bouncycastle.asn1.ASN1Encodable;
import lib.org.bouncycastle.asn1.ASN1Encoding;
import lib.org.bouncycastle.asn1.ASN1Integer;
import lib.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import lib.org.bouncycastle.asn1.ASN1Primitive;
import lib.org.bouncycastle.asn1.ASN1Sequence;
import lib.org.bouncycastle.asn1.DERBitString;
import lib.org.bouncycastle.asn1.DERNull;
import lib.org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import lib.org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import lib.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import lib.org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import lib.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import lib.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import lib.org.bouncycastle.asn1.x9.X962Parameters;
import lib.org.bouncycastle.asn1.x9.X9ECParameters;
import lib.org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import lib.org.bouncycastle.crypto.params.ECDomainParameters;
import lib.org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.JcajceUtilECUtil;
import lib.org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import lib.org.bouncycastle.jce.interfaces.ECPointEncoder;
import lib.org.bouncycastle.jce.interfaces.JceECPrivateKey;
import lib.org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import lib.org.bouncycastle.jce.spec.ECNamedCurveSpec;
import lib.org.bouncycastle.math.ec.ECCurve;
import lib.org.bouncycastle.util.Strings;

public class JceProviderJCEECPrivateKey
    implements ECPrivateKey, JceECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
{
    private String          algorithm = "EC";
    private BigInteger      d;
    private ECParameterSpec ecSpec;
    private boolean         withCompression;

    private DERBitString publicKey;

    private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected JceProviderJCEECPrivateKey()
    {
    }

    public JceProviderJCEECPrivateKey(
        ECPrivateKey    key)
    {
        this.d = key.getS();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
    }

    public JceProviderJCEECPrivateKey(
        String              algorithm,
        lib.org.bouncycastle.jce.spec.ECPrivateKeySpec     spec)
    {
        this.algorithm = algorithm;
        this.d = spec.getD();

        if (spec.getParams() != null) // can be null if implicitlyCA
        {
            ECCurve curve = spec.getParams().getCurve();
            EllipticCurve ellipticCurve;

            ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
        }
        else
        {
            this.ecSpec = null;
        }
    }


    public JceProviderJCEECPrivateKey(
        String              algorithm,
        ECPrivateKeySpec    spec)
    {
        this.algorithm = algorithm;
        this.d = spec.getS();
        this.ecSpec = spec.getParams();
    }

    public JceProviderJCEECPrivateKey(
        String             algorithm,
        JceProviderJCEECPrivateKey key)
    {
        this.algorithm = algorithm;
        this.d = key.d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.attrCarrier = key.attrCarrier;
        this.publicKey = key.publicKey;
    }

    public JceProviderJCEECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params,
        JCEECPublicKey          pubKey,
        ECParameterSpec         spec)
    {
        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            ECDomainParameters dp = params.getParameters();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(dp.getG()),
                dp.getN(),
                dp.getH().intValue());
        }
        else
        {
            this.ecSpec = spec;
        }

        publicKey = getPublicKeyDetails(pubKey);
    }

    public JceProviderJCEECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params,
        JCEECPublicKey          pubKey,
        lib.org.bouncycastle.jce.spec.ECParameterSpec         spec)
    {
        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            ECDomainParameters dp = params.getParameters();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(dp.getG()),
                dp.getN(),
                dp.getH().intValue());
        }
        else
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());
            
            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(spec.getG()),
                spec.getN(),
                spec.getH().intValue());
        }

        publicKey = getPublicKeyDetails(pubKey);
    }

    public JceProviderJCEECPrivateKey(
        String                  algorithm,
        ECPrivateKeyParameters  params)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.ecSpec = null;
    }

    JceProviderJCEECPrivateKey(
        PrivateKeyInfo      info)
        throws IOException
    {
        populateFromPrivKeyInfo(info);
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info)
        throws IOException
    {
        X962Parameters params = new X962Parameters((ASN1Primitive)info.getPrivateKeyAlgorithm().getParameters());

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
            X9ECParameters ecP = JcajceUtilECUtil.getNamedCurveByOid(oid);

            if (ecP == null) // GOST Curve
            {
                ECDomainParameters gParam = ECGOST3410NamedCurves.getByOID(oid);
                EllipticCurve ellipticCurve = EC5Util.convertCurve(gParam.getCurve(), gParam.getSeed());

                ecSpec = new ECNamedCurveSpec(
                    ECGOST3410NamedCurves.getName(oid),
                    ellipticCurve,
                    EC5Util.convertPoint(gParam.getG()),
                    gParam.getN(),
                    gParam.getH());
            }
            else
            {
                EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

                ecSpec = new ECNamedCurveSpec(
                    JcajceUtilECUtil.getCurveName(oid),
                    ellipticCurve,
                    EC5Util.convertPoint(ecP.getG()),
                    ecP.getN(),
                    ecP.getH());
            }
        }
        else if (params.isImplicitlyCA())
        {
            ecSpec = null;
        }
        else
        {
            X9ECParameters      ecP = X9ECParameters.getInstance(params.getParameters());
            EllipticCurve       ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(ecP.getG()),
                ecP.getN(),
                ecP.getH().intValue());
        }

        ASN1Encodable privKey = info.parsePrivateKey();
        if (privKey instanceof ASN1Integer)
        {
            ASN1Integer          derD = ASN1Integer.getInstance(privKey);

            this.d = derD.getValue();
        }
        else
        {
            ECPrivateKeyStructure ec = new ECPrivateKeyStructure((ASN1Sequence)privKey);

            this.d = ec.getKey();
            this.publicKey = ec.getPublicKey();
        }
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        X962Parameters          params;

        if (ecSpec instanceof ECNamedCurveSpec)
        {
            ASN1ObjectIdentifier curveOid = JcajceUtilECUtil.getNamedCurveOid(((ECNamedCurveSpec)ecSpec).getName());
            if (curveOid == null)  // guess it's the OID
            {
                curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName());
            }
            params = new X962Parameters(curveOid);
        }
        else if (ecSpec == null)
        {
            params = new X962Parameters(DERNull.INSTANCE);
        }
        else
        {
            ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

            X9ECParameters ecP = new X9ECParameters(
                curve,
                EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression),
                ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());

            params = new X962Parameters(ecP);
        }
        
        PrivateKeyInfo          info;
        ECPrivateKeyStructure keyStructure;

        if (publicKey != null)
        {
            keyStructure = new ECPrivateKeyStructure(this.getS(), publicKey, params);
        }
        else
        {
            keyStructure = new ECPrivateKeyStructure(this.getS(), params);
        }

        try
        {
            if (algorithm.equals("ECGOST3410"))
            {
                info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params.toASN1Primitive()), keyStructure.toASN1Primitive());
            }
            else
            {

                info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive()), keyStructure.toASN1Primitive());
            }

            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public lib.org.bouncycastle.jce.spec.ECParameterSpec getParameters()
    {
        if (ecSpec == null)
        {
            return null;
        }
        
        return EC5Util.convertSpec(ecSpec, withCompression);
    }

    lib.org.bouncycastle.jce.spec.ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return EC5Util.convertSpec(ecSpec, withCompression);
        }

        return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public BigInteger getS()
    {
        return d;
    }

    public BigInteger getD()
    {
        return d;
    }
    
    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable        attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }

    public void setPointFormat(String style)
    {
       withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof JceProviderJCEECPrivateKey))
        {
            return false;
        }

        JceProviderJCEECPrivateKey other = (JceProviderJCEECPrivateKey)o;

        return getD().equals(other.getD()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    public String toString()
    {
        StringBuffer    buf = new StringBuffer();
        String          nl = Strings.lineSeparator();

        buf.append("EC Private Key").append(nl);
        buf.append("             S: ").append(this.d.toString(16)).append(nl);

        return buf.toString();

    }

    private DERBitString getPublicKeyDetails(JCEECPublicKey   pub)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        }
        catch (IOException e)
        {   // should never happen
            return null;
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        byte[] enc = (byte[])in.readObject();

        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

        this.algorithm = (String)in.readObject();
        this.withCompression = in.readBoolean();
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();

        attrCarrier.readObject(in);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.writeObject(this.getEncoded());
        out.writeObject(algorithm);
        out.writeBoolean(withCompression);

        attrCarrier.writeObject(out);
    }
}
