package lib.org.bouncycastle.crypto.tls;

import lib.org.bouncycastle.util.Arrays;
import lib.org.bouncycastle.util.Strings;

public class BasicTlsPSKIdentity
    implements TlsPSKIdentity
{
    protected byte[] identity;
    protected byte[] psk;

    public BasicTlsPSKIdentity(byte[] identity, byte[] psk)
    {
        this.identity = Arrays.clone(identity);
        this.psk = Arrays.clone(psk);
    }

    public BasicTlsPSKIdentity(String identity, byte[] psk)
    {
        this.identity = Strings.toUTF8ByteArray(identity);
        this.psk = Arrays.clone(psk);
    }

    public void skipIdentityHint()
    {
    }

    public void notifyIdentityHint(byte[] psk_identity_hint)
    {
    }

    public byte[] getPSKIdentity()
    {
        return identity;
    }

    public byte[] getPSK()
    {
        return psk;
    }

}
