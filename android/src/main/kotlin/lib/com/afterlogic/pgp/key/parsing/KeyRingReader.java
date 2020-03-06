
package lib.com.afterlogic.pgp.key.parsing;




import lib.com.afterlogic.pgp.key.collection.PGPKeyRingUtil;

import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPUtil;
import lib.org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

public class KeyRingReader {

    public static final Charset UTF8 = Charset.forName("UTF-8");

    public
    PGPPublicKeyRing publicKeyRing( InputStream inputStream) throws IOException {
        return readPublicKeyRing(inputStream);
    }

    public PGPPublicKeyRing publicKeyRing( byte[] bytes) throws IOException {
        return publicKeyRing(new ByteArrayInputStream(bytes));
    }

    public PGPPublicKeyRing publicKeyRing( String asciiArmored) throws IOException {
        return publicKeyRing(asciiArmored.getBytes(UTF8));
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection( InputStream inputStream)
            throws IOException, PGPException {
        return readPublicKeyRingCollection(inputStream);
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection( byte[] bytes) throws IOException, PGPException {
        return publicKeyRingCollection(new ByteArrayInputStream(bytes));
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection( String asciiArmored) throws IOException, PGPException {
        return publicKeyRingCollection(asciiArmored.getBytes(UTF8));
    }

    public PGPSecretKeyRing secretKeyRing( InputStream inputStream) throws IOException, PGPException {
        return readSecretKeyRing(inputStream);
    }

    public PGPSecretKeyRing secretKeyRing( byte[] bytes) throws IOException, PGPException {
        return secretKeyRing(new ByteArrayInputStream(bytes));
    }

    public PGPSecretKeyRing secretKeyRing( String asciiArmored) throws IOException, PGPException {
        return secretKeyRing(asciiArmored.getBytes(UTF8));
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection( InputStream inputStream)
            throws IOException, PGPException {
        return readSecretKeyRingCollection(inputStream);
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection( byte[] bytes) throws IOException, PGPException {
        return secretKeyRingCollection(new ByteArrayInputStream(bytes));
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection( String asciiArmored) throws IOException, PGPException {
        return secretKeyRingCollection(asciiArmored.getBytes(UTF8));
    }

    public PGPKeyRingUtil keyRing(InputStream publicIn, InputStream secretIn) throws IOException, PGPException {
        return readKeyRing(publicIn, secretIn);
    }

    public PGPKeyRingUtil keyRing(byte[] publicBytes, byte[] secretBytes) throws IOException, PGPException {
        return keyRing(
                publicBytes != null ? new ByteArrayInputStream(publicBytes) : null,
                secretBytes != null ? new ByteArrayInputStream(secretBytes) : null
        );
    }

    public PGPKeyRingUtil keyRing(String asciiPublic, String asciiSecret) throws IOException, PGPException {
        return keyRing(
                asciiPublic != null ? asciiPublic.getBytes(UTF8) : null,
                asciiSecret != null ? asciiSecret.getBytes(UTF8) : null
        );
    }



    public static PGPPublicKeyRing readPublicKeyRing( InputStream inputStream) throws IOException {
        return new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPPublicKeyRingCollection readPublicKeyRingCollection( InputStream inputStream)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRing readSecretKeyRing( InputStream inputStream) throws IOException, PGPException {
        return new PGPSecretKeyRing(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection( InputStream inputStream)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPKeyRingUtil readKeyRing(InputStream publicIn, InputStream secretIn) throws IOException, PGPException {

        if (publicIn == null && secretIn == null) {
            throw new NullPointerException("publicIn and secretIn cannot be BOTH null.");
        }

        PGPPublicKeyRing publicKeys = null;
        if (publicIn != null) {
            publicKeys = readPublicKeyRing(publicIn);
        }
        PGPSecretKeyRing secretKeys = null;
        if (secretIn != null) {
            secretKeys = readSecretKeyRing(secretIn);
        }

        if (secretKeys == null) {
            return new PGPKeyRingUtil(publicKeys);
        }

        if (publicKeys == null) {
            return new PGPKeyRingUtil(secretKeys);
        }

        return new PGPKeyRingUtil(publicKeys, secretKeys);
    }
}
