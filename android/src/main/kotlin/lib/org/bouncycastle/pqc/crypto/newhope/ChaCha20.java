package lib.org.bouncycastle.pqc.crypto.newhope;

import lib.org.bouncycastle.crypto.engines.ChaChaEngine;
import lib.org.bouncycastle.crypto.params.KeyParameter;
import lib.org.bouncycastle.crypto.params.ParametersWithIV;

class ChaCha20
{
    static void process(byte[] key, byte[] nonce, byte[] buf, int off, int len)
    {
        ChaChaEngine e = new ChaChaEngine(20);
        e.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        e.processBytes(buf, off, len, buf, off);
    }
}
