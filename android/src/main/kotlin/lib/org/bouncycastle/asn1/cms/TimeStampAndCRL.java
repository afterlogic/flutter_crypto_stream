package lib.org.bouncycastle.asn1.cms;

import lib.org.bouncycastle.asn1.ASN1EncodableVector;
import lib.org.bouncycastle.asn1.ASN1Object;
import lib.org.bouncycastle.asn1.ASN1Primitive;
import lib.org.bouncycastle.asn1.ASN1Sequence;
import lib.org.bouncycastle.asn1.DERSequence;
import lib.org.bouncycastle.asn1.x509.CertificateList;

/**
 * <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>
 * Binding Documents with Asn1CmsTime-Stamps; TimeStampAndCRL object.
 * <pre>
 * TimeStampAndCRL ::= SEQUENCE {
 *     timeStamp   TimeStampToken,          -- according to RFC 3161
 *     crl         CertificateList OPTIONAL -- according to RFC 5280
 *  }
 * </pre>
 */
public class TimeStampAndCRL
    extends ASN1Object
{
    private Asn1CmsContentInfo timeStamp;
    private CertificateList crl;

    public TimeStampAndCRL(Asn1CmsContentInfo timeStamp)
    {
        this.timeStamp = timeStamp;
    }

    private TimeStampAndCRL(ASN1Sequence seq)
    {
        this.timeStamp = Asn1CmsContentInfo.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2)
        {
            this.crl = CertificateList.getInstance(seq.getObjectAt(1));
        }
    }

    /**
     * Return a TimeStampAndCRL object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link TimeStampAndCRL} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with TimeStampAndCRL structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static TimeStampAndCRL getInstance(Object obj)
    {
        if (obj instanceof TimeStampAndCRL)
        {
            return (TimeStampAndCRL)obj;
        }
        else if (obj != null)
        {
            return new TimeStampAndCRL(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public Asn1CmsContentInfo getTimeStampToken()
    {
        return this.timeStamp;
    }

    /** @deprecated use getCRL() */
    public CertificateList getCertificateList()
    {
        return this.crl;
    }

    public CertificateList getCRL()
    {
        return this.crl;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(timeStamp);

        if (crl != null)
        {
            v.add(crl);
        }

        return new DERSequence(v);
    }
}
