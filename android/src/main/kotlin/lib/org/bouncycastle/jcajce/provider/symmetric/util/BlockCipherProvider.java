package lib.org.bouncycastle.jcajce.provider.symmetric.util;

import lib.org.bouncycastle.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
