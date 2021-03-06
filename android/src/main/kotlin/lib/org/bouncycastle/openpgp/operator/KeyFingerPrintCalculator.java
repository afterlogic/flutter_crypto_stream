package lib.org.bouncycastle.openpgp.operator;

import lib.org.bouncycastle.bcpg.PublicKeyPacket;
import lib.org.bouncycastle.openpgp.PGPException;

public interface KeyFingerPrintCalculator
{
    byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException;
}
