package lib.org.bouncycastle.crypto.tls;

import java.io.IOException;

import lib.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface TlsAgreementCredentials
    extends TlsCredentials
{
    byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey)
        throws IOException;
}
