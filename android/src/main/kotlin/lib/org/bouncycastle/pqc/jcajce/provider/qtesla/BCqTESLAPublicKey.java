package lib.org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import lib.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import lib.org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import lib.org.bouncycastle.pqc.crypto.util.PqcCryptoPublicKeyFactory;
import lib.org.bouncycastle.pqc.crypto.util.PqcSubjectPublicKeyInfoFactory;
import lib.org.bouncycastle.pqc.jcajce.interfaces.QTESLAKey;
import lib.org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
import lib.org.bouncycastle.util.Arrays;

public class BCqTESLAPublicKey
    implements PublicKey, QTESLAKey
{
    private static final long serialVersionUID = 1L;

    private transient QTESLAPublicKeyParameters keyParams;

    public BCqTESLAPublicKey(
        QTESLAPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    public BCqTESLAPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.keyParams = (QTESLAPublicKeyParameters) PqcCryptoPublicKeyFactory.createKey(keyInfo);
    }

    /**
     * @return name of the algorithm
     */
    public final String getAlgorithm()
    {
        return QTESLASecurityCategory.getName(keyParams.getSecurityCategory());
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = PqcSubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParams);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    public QTESLAParameterSpec getParams()
    {
        return new QTESLAParameterSpec(getAlgorithm());
    }
    
    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCqTESLAPublicKey)
        {
            BCqTESLAPublicKey otherKey = (BCqTESLAPublicKey)o;

            return keyParams.getSecurityCategory() == otherKey.keyParams.getSecurityCategory()
                && Arrays.areEqual(keyParams.getPublicData(), otherKey.keyParams.getPublicData());
        }

        return false;
    }

    public int hashCode()
    {
        return keyParams.getSecurityCategory() + 37 * Arrays.hashCode(keyParams.getPublicData());
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
