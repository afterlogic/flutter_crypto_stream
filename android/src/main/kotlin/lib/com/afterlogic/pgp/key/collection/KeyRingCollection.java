
package lib.com.afterlogic.pgp.key.collection;


import lib.com.afterlogic.pgp.key.parsing.KeyRingReader;

import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyRingCollection {

    private static final Logger LOGGER = Logger.getLogger(KeyRingCollection.class.getName());

    private PGPPublicKeyRingCollection publicKeys;
    private PGPSecretKeyRingCollection secretKeys;

    public KeyRingCollection(PGPPublicKeyRingCollection publicKeyRings, PGPSecretKeyRingCollection secretKeyRings) {
        this.publicKeys = publicKeyRings;
        this.secretKeys = secretKeyRings;
    }

    public KeyRingCollection(File pubRingFile, File secRingFile) throws IOException, PGPException {

        if (pubRingFile == null && secRingFile == null) {
            throw new NullPointerException("pubRingFile and secRingFile cannot BOTH be null.");
        }

        if (pubRingFile != null) {
            InputStream pubRingIn = new FileInputStream(pubRingFile);
            this.publicKeys = new KeyRingReader().publicKeyRingCollection(pubRingIn);
            pubRingIn.close();
        }

        if (secRingFile != null) {
            InputStream secRingIn = new FileInputStream(secRingFile);
            this.secretKeys = new KeyRingReader().secretKeyRingCollection(secRingIn);
            secRingIn.close();
        }
    }

    public KeyRingCollection(PGPPublicKeyRingCollection publicKeyRings) {
        this.publicKeys = publicKeyRings;
    }

    public KeyRingCollection(PGPSecretKeyRingCollection secretKeyRings) {
        this.secretKeys = secretKeyRings;
    }

    public void importPublicKeys(PGPPublicKeyRingCollection publicKeyRings) {
        if (this.publicKeys == null) {
            this.publicKeys = publicKeyRings;
            return;
        }

        for (PGPPublicKeyRing keyRing : publicKeyRings) {
            try {
                this.publicKeys = PGPPublicKeyRingCollection.addPublicKeyRing(this.publicKeys, keyRing);
            } catch (IllegalArgumentException e) {
                LOGGER.log(Level.FINE, "Keyring " + Long.toHexString(keyRing.getPublicKey().getKeyID()) +
                        " is already included in the collection. Skip!");
            }
        }
    }

    public void importSecretKeys(PGPSecretKeyRingCollection secretKeyRings) {
        if (this.secretKeys == null) {
            this.secretKeys = secretKeyRings;
            return;
        }

        for (PGPSecretKeyRing keyRing : secretKeyRings) {
            try {
                this.secretKeys = PGPSecretKeyRingCollection.addSecretKeyRing(this.secretKeys, keyRing);
            } catch (IllegalArgumentException e) {
                LOGGER.log(Level.FINE, "Keyring " + Long.toHexString(keyRing.getPublicKey().getKeyID()) +
                        " is already included in the collection. Skip!");
            }
        }
    }
}
