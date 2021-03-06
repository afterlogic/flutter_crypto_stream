package lib.org.bouncycastle.asn1.x509;

import lib.org.bouncycastle.asn1.ASN1Integer;
import lib.org.bouncycastle.asn1.ASN1Object;
import lib.org.bouncycastle.asn1.ASN1Primitive;
import lib.org.bouncycastle.asn1.ASN1Sequence;
import lib.org.bouncycastle.asn1.ASN1TaggedObject;
import lib.org.bouncycastle.asn1.DERBitString;
import lib.org.bouncycastle.asn1.x500.X500Name;

/**
 * an X509Certificate structure.
 * <pre>
 *  X509Certificate ::= SEQUENCE {
 *      tbsCertificate          TBSCertificate,
 *      signatureAlgorithm      AlgorithmIdentifier,
 *      signature               BIT STRING
 *  }
 * </pre>
 */
public class X509Certificate
    extends ASN1Object
{
    ASN1Sequence  seq;
    TBSCertificate tbsCert;
    AlgorithmIdentifier     sigAlgId;
    DERBitString            sig;

    public static X509Certificate getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static X509Certificate getInstance(
        Object  obj)
    {
        if (obj instanceof X509Certificate)
        {
            return (X509Certificate)obj;
        }
        else if (obj != null)
        {
            return new X509Certificate(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private X509Certificate(
        ASN1Sequence seq)
    {
        this.seq = seq;

        //
        // correct x509 certficate
        //
        if (seq.size() == 3)
        {
            tbsCert = TBSCertificate.getInstance(seq.getObjectAt(0));
            sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

            sig = DERBitString.getInstance(seq.getObjectAt(2));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for a certificate");
        }
    }

    public TBSCertificate getTBSCertificate()
    {
        return tbsCert;
    }

    public ASN1Integer getVersion()
    {
        return tbsCert.getVersion();
    }

    public int getVersionNumber()
    {
        return tbsCert.getVersionNumber();
    }

    public ASN1Integer getSerialNumber()
    {
        return tbsCert.getSerialNumber();
    }

    public X500Name getIssuer()
    {
        return tbsCert.getIssuer();
    }

    public Asn1X509Time getStartDate()
    {
        return tbsCert.getStartDate();
    }

    public Asn1X509Time getEndDate()
    {
        return tbsCert.getEndDate();
    }

    public X500Name getSubject()
    {
        return tbsCert.getSubject();
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return tbsCert.getSubjectPublicKeyInfo();
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return sigAlgId;
    }

    public DERBitString getSignature()
    {
        return sig;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}
