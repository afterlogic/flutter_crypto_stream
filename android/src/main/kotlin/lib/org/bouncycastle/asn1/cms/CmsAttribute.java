package lib.org.bouncycastle.asn1.cms;

import lib.org.bouncycastle.asn1.ASN1Encodable;
import lib.org.bouncycastle.asn1.ASN1EncodableVector;
import lib.org.bouncycastle.asn1.ASN1Object;
import lib.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import lib.org.bouncycastle.asn1.ASN1Primitive;
import lib.org.bouncycastle.asn1.ASN1Sequence;
import lib.org.bouncycastle.asn1.ASN1Set;
import lib.org.bouncycastle.asn1.DERSequence;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#page-14">RFC 5652</a>:
 * CmsAttribute is a pair of OID (as type identifier) + set of values.
 * <p>
 * <pre>
 * CmsAttribute ::= SEQUENCE {
 *     attrType OBJECT IDENTIFIER,
 *     attrValues SET OF AttributeValue
 * }
 * 
 * AttributeValue ::= ANY
 * </pre>
 * <p>
 * General rule on values is that same AttributeValue must not be included
 * multiple times into the set. That is, if the value is a SET OF INTEGERs,
 * then having same value repeated is wrong: (1, 1), but different values is OK: (1, 2).
 * Normally the AttributeValue syntaxes are more complicated than that.
 * <p>
 * General rule of CmsAttribute usage is that the {@link Attributes} containers
 * must not have multiple CmsAttribute:s with same attrType (OID) there.
 */
public class CmsAttribute
    extends ASN1Object
{
    private ASN1ObjectIdentifier attrType;
    private ASN1Set             attrValues;

    /**
     * Return an CmsAttribute object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link CmsAttribute} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with CmsAttribute structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static CmsAttribute getInstance(
        Object o)
    {
        if (o instanceof CmsAttribute)
        {
            return (CmsAttribute)o;
        }
        
        if (o != null)
        {
            return new CmsAttribute(ASN1Sequence.getInstance(o));
        }

        return null;
    }
    
    private CmsAttribute(
        ASN1Sequence seq)
    {
        attrType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        attrValues = (ASN1Set)seq.getObjectAt(1);
    }

    public CmsAttribute(
        ASN1ObjectIdentifier attrType,
        ASN1Set             attrValues)
    {
        this.attrType = attrType;
        this.attrValues = attrValues;
    }

    public ASN1ObjectIdentifier getAttrType()
    {
        return attrType;
    }
    
    public ASN1Set getAttrValues()
    {
        return attrValues;
    }

    public ASN1Encodable[] getAttributeValues()
    {
        return attrValues.toArray();
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attrType);
        v.add(attrValues);

        return new DERSequence(v);
    }
}
