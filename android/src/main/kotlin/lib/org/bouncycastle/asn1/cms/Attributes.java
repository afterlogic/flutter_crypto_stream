package lib.org.bouncycastle.asn1.cms;

import lib.org.bouncycastle.asn1.ASN1EncodableVector;
import lib.org.bouncycastle.asn1.ASN1Object;
import lib.org.bouncycastle.asn1.ASN1Primitive;
import lib.org.bouncycastle.asn1.ASN1Set;
import lib.org.bouncycastle.asn1.ASN1TaggedObject;
import lib.org.bouncycastle.asn1.DLSet;

/**
 * <a href="http://tools.ietf.org/html/rfc5652">RFC 5652</a> defines
 * 5 "SET OF CmsAttribute" entities with 5 different names.
 * This is common implementation for them all:
 * <pre>
 *   SignedAttributes      ::= SET SIZE (1..MAX) OF CmsAttribute
 *   UnsignedAttributes    ::= SET SIZE (1..MAX) OF CmsAttribute
 *   UnprotectedAttributes ::= SET SIZE (1..MAX) OF CmsAttribute
 *   AuthAttributes        ::= SET SIZE (1..MAX) OF CmsAttribute
 *   UnauthAttributes      ::= SET SIZE (1..MAX) OF CmsAttribute
 *
 * Attributes ::=
 *   SET SIZE(1..MAX) OF CmsAttribute
 * </pre>
 */
public class Attributes
    extends ASN1Object
{
    private ASN1Set attributes;

    private Attributes(ASN1Set set)
    {
        attributes = set;
    }

    public Attributes(ASN1EncodableVector v)
    {
        attributes = new DLSet(v);
    }

    /**
     * Return an CmsAttribute set object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link Attributes} object
     * <li> {@link ASN1Set#getInstance(Object) ASN1Set} input formats with Attributes structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static Attributes getInstance(Object obj)
    {
        if (obj instanceof Attributes)
        {
            return (Attributes)obj;
        }
        else if (obj != null)
        {
            return new Attributes(ASN1Set.getInstance(obj));
        }

        return null;
    }

    public static Attributes getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Set.getInstance(obj, explicit));
    }

    public CmsAttribute[] getAttributes()
    {
        CmsAttribute[] rv = new CmsAttribute[attributes.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = CmsAttribute.getInstance(attributes.getObjectAt(i));
        }

        return rv;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return attributes;
    }
}
