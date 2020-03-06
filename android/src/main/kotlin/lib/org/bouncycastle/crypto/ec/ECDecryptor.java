package lib.org.bouncycastle.crypto.ec;

import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.math.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}
