package lib.org.bouncycastle.crypto.prng;

import lib.org.bouncycastle.crypto.prng.drbg.SP80090DRBG;

interface DRBGProvider
{
    SP80090DRBG get(EntropySource entropySource);
}
