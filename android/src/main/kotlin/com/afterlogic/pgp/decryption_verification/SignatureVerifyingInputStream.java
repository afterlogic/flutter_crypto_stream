
package com.afterlogic.pgp.decryption_verification;



import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import com.afterlogic.pgp.key.OpenPgpV4Fingerprint;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SignatureVerifyingInputStream extends FilterInputStream {

    private static final Logger LOGGER = Logger.getLogger(SignatureVerifyingInputStream.class.getName());
    private static final Level LEVEL = Level.FINE;

    private final PGPObjectFactory objectFactory;
    private final Map<OpenPgpV4Fingerprint, PGPOnePassSignature> onePassSignatures;
    private final OpenPgpMetadata.Builder resultBuilder;

    private boolean validated = false;

    protected SignatureVerifyingInputStream( InputStream inputStream,
                                             PGPObjectFactory objectFactory,
                                             Map<OpenPgpV4Fingerprint, PGPOnePassSignature> onePassSignatures,
                                             OpenPgpMetadata.Builder resultBuilder) {
        super(inputStream);
        this.objectFactory = objectFactory;
        this.resultBuilder = resultBuilder;
        this.onePassSignatures = onePassSignatures;

        LOGGER.log(LEVEL, "Begin verifying OnePassSignatures");
    }

    private void updateOnePassSignatures(byte data) {
        for (PGPOnePassSignature signature : onePassSignatures.values()) {
            signature.update(data);
        }
    }

    private void updateOnePassSignatures(byte[] b, int off, int len) {
        for (PGPOnePassSignature signature : onePassSignatures.values()) {
            signature.update(b, off, len);
        }
    }

    private void validateOnePassSignatures() throws IOException {

        if (validated) {
            LOGGER.log(LEVEL, "Validated signatures already. Skip");
            return;
        }

        validated = true;

        if (onePassSignatures.isEmpty()) {
            LOGGER.log(LEVEL, "No One-Pass-Signatures found -> No validation");
            return;
        }

        try {
            PGPSignatureList signatureList = null;
            Object obj = objectFactory.nextObject();
            while (obj !=  null && signatureList == null) {
                if (obj instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) obj;
                } else {
                    obj = objectFactory.nextObject();
                }
            }

            if (signatureList == null || signatureList.isEmpty()) {
                throw new IOException("Verification failed - No Signatures found");
            }

            for (PGPSignature signature : signatureList) {
                OpenPgpV4Fingerprint fingerprint = null;
                for (OpenPgpV4Fingerprint f : onePassSignatures.keySet()) {
                    if (f.getKeyId() == signature.getKeyID()) {
                        fingerprint = f;
                        break;
                    }
                }

                PGPOnePassSignature onePassSignature;
                if (fingerprint == null || (onePassSignature = onePassSignatures.get(fingerprint)) == null) {
                    LOGGER.log(LEVEL, "Found Signature without respective OnePassSignature packet -> skip");
                    continue;
                }

                if (!onePassSignature.verify(signature)) {
                    throw new SignatureException("Bad Signature of key " + signature.getKeyID());
                } else {
                    LOGGER.log(LEVEL, "Verified signature of key " + Long.toHexString(signature.getKeyID()));
                    resultBuilder.addVerifiedSignatureFingerprint(fingerprint);
                }
            }
        } catch (PGPException | SignatureException e) {
            throw new IOException(e.getMessage(), e);
        }

    }

    @Override
    public int read() throws IOException {
        final int data = super.read();
        final boolean endOfStream = data == -1;
        if (endOfStream) {
            validateOnePassSignatures();
        } else {
            updateOnePassSignatures((byte) data);
        }
        return data;
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int read = super.read(b, off, len);

        final boolean endOfStream = read == -1;
        if (endOfStream) {
            validateOnePassSignatures();
        } else {
            updateOnePassSignatures(b, off, read);
        }
        return read;
    }

    @Override
    public long skip(long n) {
        throw new UnsupportedOperationException("skip() is not supported");
    }

    @Override
    public synchronized void mark(int readlimit) {
        throw new UnsupportedOperationException("mark() not supported");
    }

    @Override
    public synchronized void reset() {
        throw new UnsupportedOperationException("reset() is not supported");
    }

    @Override
    public boolean markSupported() {
        return false;
    }
}
