package lib.org.bouncycastle.crypto.tls;

import lib.org.bouncycastle.crypto.AsymmetricBlockCipher;
import lib.org.bouncycastle.crypto.CipherParameters;
import lib.org.bouncycastle.crypto.CryptoException;
import lib.org.bouncycastle.crypto.Digest;
import lib.org.bouncycastle.crypto.Signer;
import lib.org.bouncycastle.crypto.digests.NullDigest;
import lib.org.bouncycastle.crypto.encodings.PKCS1Encoding;
import lib.org.bouncycastle.crypto.engines.RSABlindedEngine;
import lib.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import lib.org.bouncycastle.crypto.params.ParametersWithRandom;
import lib.org.bouncycastle.crypto.params.RSAKeyParameters;
import lib.org.bouncycastle.crypto.signers.GenericSigner;
import lib.org.bouncycastle.crypto.signers.RSADigestSigner;

public class TlsRSASigner
    extends AbstractTlsSigner
{
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm,
        AsymmetricKeyParameter privateKey, byte[] hash)
        throws CryptoException
    {
        Signer signer = makeSigner(algorithm, true, true,
            new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
        signer.update(hash, 0, hash.length);
        return signer.generateSignature();
    }

    public boolean verifyRawSignature(SignatureAndHashAlgorithm algorithm, byte[] sigBytes,
        AsymmetricKeyParameter publicKey, byte[] hash)
        throws CryptoException
    {
        Signer signer = makeSigner(algorithm, true, false, publicKey);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(sigBytes);
    }

    public Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey)
    {
        return makeSigner(algorithm, false, true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
    }

    public Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey)
    {
        return makeSigner(algorithm, false, false, publicKey);
    }

    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof RSAKeyParameters && !publicKey.isPrivate();
    }

    protected Signer makeSigner(SignatureAndHashAlgorithm algorithm, boolean raw, boolean forSigning,
        CipherParameters cp)
    {
        if ((algorithm != null) != TlsUtils.isTLSv12(context))
        {
            throw new IllegalStateException();
        }

        if (algorithm != null && algorithm.getSignature() != SignatureAlgorithm.rsa)
        {
            throw new IllegalStateException();
        }

        Digest d;
        if (raw)
        {
            d = new NullDigest();
        }
        else if (algorithm == null)
        {
            d = new CombinedHash();
        }
        else
        {
            d = TlsUtils.createHash(algorithm.getHash());
        }

        Signer s;
        if (algorithm != null)
        {
            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
            s = new RSADigestSigner(d, TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
        }
        else
        {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
            s = new GenericSigner(createRSAImpl(), d);
        }
        s.init(forSigning, cp);
        return s;
    }

    protected AsymmetricBlockCipher createRSAImpl()
    {
        /*
         * RFC 5246 7.4.7.1. Implementation note: It is now known that remote timing-based attacks
         * on TLS are possible, at least when the client and server are on the same LAN.
         * Accordingly, implementations that use static RSA keys MUST use RSA blinding or some other
         * anti-timing technique, as described in [TIMING].
         */
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
