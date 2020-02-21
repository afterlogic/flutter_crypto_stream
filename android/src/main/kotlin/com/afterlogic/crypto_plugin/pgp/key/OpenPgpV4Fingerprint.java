
package com.afterlogic.crypto_plugin.pgp.key;



import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;


public class OpenPgpV4Fingerprint implements CharSequence, Comparable<OpenPgpV4Fingerprint> {

    private final String fingerprint;


    public OpenPgpV4Fingerprint( String fingerprint) {
        String fp = fingerprint.trim().toUpperCase();
        if (!isValid(fp)) {
            throw new IllegalArgumentException("Fingerprint " + fingerprint +
                    " does not appear to be a valid OpenPGP v4 fingerprint.");
        }
        this.fingerprint = fp;
    }

    public OpenPgpV4Fingerprint( byte[] bytes) {
        this(new String(bytes, Charset.forName("UTF-8")));
    }

    public OpenPgpV4Fingerprint( PGPPublicKey key) {
        this(Hex.encode(key.getFingerprint()));
        if (key.getVersion() != 4) {
            throw new IllegalArgumentException("Key is not a v4 OpenPgp key.");
        }
    }

    public OpenPgpV4Fingerprint( PGPSecretKey key) {
        this(key.getPublicKey());
    }

    public OpenPgpV4Fingerprint( PGPPublicKeyRing ring) {
        this(ring.getPublicKey());
    }

    public OpenPgpV4Fingerprint( PGPSecretKeyRing ring) {
        this(ring.getPublicKey());
    }


    private static boolean isValid( String fp) {
        return fp.matches("[0-9A-F]{40}");
    }


    public long getKeyId() {
        byte[] bytes = Hex.decode(toString().getBytes(Charset.forName("UTF-8")));
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        buf.position(12);
        return buf.getLong();

    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (!(other instanceof CharSequence)) {
            return false;
        }

        return this.toString().equals(other.toString());
    }

    @Override
    public int hashCode() {
        return fingerprint.hashCode();
    }

    @Override
    public int length() {
        return fingerprint.length();
    }

    @Override
    public char charAt(int i) {
        return fingerprint.charAt(i);
    }

    @Override
    public CharSequence subSequence(int i, int i1) {
        return fingerprint.subSequence(i, i1);
    }

    @Override
    public String toString() {
        return fingerprint;
    }

    @Override
    public int compareTo( OpenPgpV4Fingerprint openPgpV4Fingerprint) {
        return fingerprint.compareTo(openPgpV4Fingerprint.fingerprint);
    }
}
