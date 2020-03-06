package lib.org.bouncycastle.crypto.ec;

import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.math.ec.ECPoint;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}
