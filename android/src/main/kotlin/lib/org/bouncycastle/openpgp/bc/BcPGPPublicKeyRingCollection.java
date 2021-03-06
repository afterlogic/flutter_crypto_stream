package lib.org.bouncycastle.openpgp.bc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public class BcPGPPublicKeyRingCollection
    extends PGPPublicKeyRingCollection
{
    public BcPGPPublicKeyRingCollection(byte[] encoding)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding));
    }

    public BcPGPPublicKeyRingCollection(InputStream in)
        throws IOException, PGPException
    {
        super(in, new BcKeyFingerprintCalculator());
    }

    public BcPGPPublicKeyRingCollection(Collection collection)
        throws IOException, PGPException
    {
        super(collection);
    }
}
