package lib.org.bouncycastle.pqc.jcajce.provider.newhope;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import lib.org.bouncycastle.asn1.ASN1Set;
import lib.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import lib.org.bouncycastle.pqc.crypto.util.PqcCryptoPrivateKeyFactory;
import lib.org.bouncycastle.pqc.crypto.util.PqcCryptoPrivateKeyInfoFactory;
import lib.org.bouncycastle.pqc.jcajce.interfaces.NHPrivateKey;
import lib.org.bouncycastle.util.Arrays;

public class BCNHPrivateKey
    implements NHPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient NHPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCNHPrivateKey(
        NHPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCNHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (NHPrivateKeyParameters) PqcCryptoPrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this NH private key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (!(o instanceof BCNHPrivateKey))
        {
            return false;
        }
        BCNHPrivateKey otherKey = (BCNHPrivateKey)o;

        return Arrays.areEqual(params.getSecData(), otherKey.params.getSecData());
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getSecData());
    }

    /**
     * @return name of the algorithm - "NH"
     */
    public final String getAlgorithm()
    {
        return "NH";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PqcCryptoPrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public short[] getSecretData()
    {
        return params.getSecData();
    }

    CipherParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
