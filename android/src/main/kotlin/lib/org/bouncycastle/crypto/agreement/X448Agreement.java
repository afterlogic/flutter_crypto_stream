package lib.org.bouncycastle.crypto.agreement;

import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.crypto.RawAgreement;
import lib.org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import lib.org.bouncycastle.crypto.params.X448PublicKeyParameters;

public final class X448Agreement
    implements RawAgreement
{
    private X448PrivateKeyParameters privateKey;

    public void init(CipherParameters parameters)
    {
        this.privateKey = (X448PrivateKeyParameters)parameters;
    }

    public int getAgreementSize()
    {
        return X448PrivateKeyParameters.SECRET_SIZE;
    }

    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
    {
        privateKey.generateSecret((X448PublicKeyParameters)publicKey, buf, off);
    }
}
