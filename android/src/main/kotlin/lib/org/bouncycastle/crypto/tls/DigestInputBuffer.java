package lib.org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;

import lib.org.bouncycastle.crypto.Digest;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(Digest d)
    {
        d.update(this.buf, 0, count);
    }
}
