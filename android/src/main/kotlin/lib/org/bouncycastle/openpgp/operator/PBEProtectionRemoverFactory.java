package lib.org.bouncycastle.openpgp.operator;

import lib.org.bouncycastle.openpgp.PGPException;

public interface PBEProtectionRemoverFactory
{
    PBESecretKeyDecryptor createDecryptor(String protection)
        throws PGPException;
}
