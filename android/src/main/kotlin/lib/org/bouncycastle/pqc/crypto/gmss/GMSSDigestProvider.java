package lib.org.bouncycastle.pqc.crypto.gmss;

import lib.org.bouncycastle.crypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}
