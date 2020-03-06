package lib.org.bouncycastle.bcpg.sig;

import lib.org.bouncycastle.bcpg.SignatureSubpacket;
import lib.org.bouncycastle.bcpg.SignatureSubpacketTags;
import lib.org.bouncycastle.util.Arrays;
import lib.org.bouncycastle.util.Strings;

/**
 * packet giving the User ID of the signer.
 */
public class SignerUserID 
    extends SignatureSubpacket
{
    public SignerUserID(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, isLongLength, data);
    }
    
    public SignerUserID(
        boolean    critical,
        String     userID)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, false, Strings.toUTF8ByteArray(userID));
    }
    
    public String getID()
    {
        return Strings.fromUTF8ByteArray(data);
    }

    public byte[] getRawID()
    {
        return Arrays.clone(data);
    }
}
