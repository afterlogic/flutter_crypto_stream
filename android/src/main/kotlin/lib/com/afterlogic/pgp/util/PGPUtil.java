
package lib.com.afterlogic.pgp.util;



import lib.com.afterlogic.pgp.key.selection.key.PublicKeySelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.key.impl.NoRevocation;
import lib.com.afterlogic.pgp.key.selection.key.impl.SignedByMasterKey;
import lib.com.afterlogic.pgp.key.selection.key.util.And;

import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKey;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSignature;
import lib.org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import lib.org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import lib.org.bouncycastle.util.io.Streams;
import lib.com.afterlogic.pgp.algorithm.KeyFlag;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PGPUtil {

    private static final Logger LOGGER = Logger.getLogger(PGPUtil.class.getName());


    public static PGPPublicKeyRingCollection keyRingsToKeyRingCollection( PGPPublicKeyRing... rings)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(Arrays.asList(rings));
    }

    public static PGPSecretKeyRingCollection keyRingsToKeyRingCollection( PGPSecretKeyRing... rings)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(Arrays.asList(rings));
    }

    public static PGPPublicKeyRing publicKeyRingFromSecretKeyRing( PGPSecretKeyRing secretKeys)
            throws PGPException, IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(512);
        for (PGPSecretKey secretKey : secretKeys) {
            PGPPublicKey publicKey = secretKey.getPublicKey();
            if (publicKey != null) {
                publicKey.encode(buffer, false);
            }
        }

        return new PGPPublicKeyRing(buffer.toByteArray(), new BcKeyFingerprintCalculator());
    }



    public static PGPSecretKeyRing getKeyRingFromCollection( PGPSecretKeyRingCollection collection,
                                                             Long id)
            throws PGPException {
        PGPSecretKeyRing uncleanedRing = collection.getSecretKeyRing(id);

                Set<Long> signedKeyIds = new HashSet<>();
        signedKeyIds.add(id);         Iterator<PGPPublicKey> signedPubKeys = uncleanedRing.getKeysWithSignaturesBy(id);
        while (signedPubKeys.hasNext()) {
            signedKeyIds.add(signedPubKeys.next().getKeyID());
        }

        PGPSecretKeyRing cleanedRing = uncleanedRing;
        Iterator<PGPSecretKey> secretKeys = uncleanedRing.getSecretKeys();
        while (secretKeys.hasNext()) {
            PGPSecretKey secretKey = secretKeys.next();
            if (!signedKeyIds.contains(secretKey.getKeyID())) {
                cleanedRing = PGPSecretKeyRing.removeSecretKey(cleanedRing, secretKey);
            }
        }
        return cleanedRing;
    }

    public static PGPPublicKeyRing getKeyRingFromCollection( PGPPublicKeyRingCollection collection,
                                                             Long id)
            throws PGPException {
        PGPPublicKey key = collection.getPublicKey(id);
        return removeUnassociatedKeysFromKeyRing(collection.getPublicKeyRing(id), key);
    }

    public static InputStream getPgpDecoderInputStream( byte[] bytes)
            throws IOException {
        return getPgpDecoderInputStream(new ByteArrayInputStream(bytes));
    }

    public static InputStream getPgpDecoderInputStream( InputStream inputStream)
            throws IOException {
        return lib.org.bouncycastle.openpgp.PGPUtil.getDecoderStream(inputStream);
    }

    public static byte[] getDecodedBytes( byte[] bytes)
            throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(getPgpDecoderInputStream(bytes), buffer);
        return buffer.toByteArray();
    }

    public static byte[] getDecodedBytes( InputStream inputStream)
            throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(inputStream, buffer);
        return getDecodedBytes(buffer.toByteArray());
    }


    public static PGPPublicKeyRing removeUnassociatedKeysFromKeyRing( PGPPublicKeyRing ring,
                                                                      PGPPublicKey masterKey) {
        if (!masterKey.isMasterKey()) {
            throw new IllegalArgumentException("Given key is not a master key.");
        }
                PublicKeySelectionStrategy<PGPPublicKey> selector = new And.PubKeySelectionStrategy<>(
                new SignedByMasterKey.PubkeySelectionStrategy(),
                new NoRevocation.PubKeySelectionStrategy<PGPPublicKey>());

        PGPPublicKeyRing cleaned = ring;

        Iterator<PGPPublicKey> publicKeys = ring.getPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey publicKey = publicKeys.next();
            if (!selector.accept(masterKey, publicKey)) {
                cleaned = PGPPublicKeyRing.removePublicKey(cleaned, publicKey);
            }
        }

        return cleaned;
    }


    public static PGPSecretKeyRing removeUnassociatedKeysFromKeyRing( PGPSecretKeyRing ring,
                                                                      PGPPublicKey masterKey) {
        if (!masterKey.isMasterKey()) {
            throw new IllegalArgumentException("Given key is not a master key.");
        }
                PublicKeySelectionStrategy<PGPPublicKey> selector = new And.PubKeySelectionStrategy<>(
                new SignedByMasterKey.PubkeySelectionStrategy(),
                new NoRevocation.PubKeySelectionStrategy<PGPPublicKey>());

        PGPSecretKeyRing cleaned = ring;

        Iterator<PGPSecretKey> secretKeys = ring.getSecretKeys();
        while (secretKeys.hasNext()) {
            PGPSecretKey secretKey = secretKeys.next();
            if (!selector.accept(masterKey, secretKey.getPublicKey())) {
                cleaned = PGPSecretKeyRing.removeSecretKey(cleaned, secretKey);
            }
        }

        return cleaned;
    }


    public static PGPPublicKey getMasterKeyFrom( PGPPublicKeyRing ring) {
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey k = it.next();
            if (k.isMasterKey()) {
                                return k;
            }
        }
        return null;
    }

    public static PGPPublicKey getMasterKeyFrom( PGPKeyRing ring) {
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey k = it.next();
            if (k.isMasterKey()) {
                                return k;
            }
        }
        return null;
    }

    public static Set<Long> signingKeyIds( PGPSecretKeyRing ring) {
        Set<Long> ids = new HashSet<>();
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey k = it.next();

            boolean signingKey = false;

            Iterator<?> sit = k.getSignatures();
            while (sit.hasNext()) {
                Object n = sit.next();
                if (!(n instanceof PGPSignature)) {
                    continue;
                }

                PGPSignature s = (PGPSignature) n;
                if (!s.hasSubpackets()) {
                    continue;
                }

                try {
                    s.verifyCertification(ring.getPublicKey(s.getKeyID()));
                } catch (PGPException e) {
                    LOGGER.log(Level.WARNING, "Could not verify signature on " + Long.toHexString(k.getKeyID()) + " made by " + Long.toHexString(s.getKeyID()));
                    continue;
                }

                PGPSignatureSubpacketVector hashed = s.getHashedSubPackets();
                if (KeyFlag.fromInteger(hashed.getKeyFlags()).contains(KeyFlag.SIGN_DATA)) {
                    signingKey = true;
                    break;
                }
            }

            if (signingKey) {
                ids.add(k.getKeyID());
            }
        }
        return ids;
    }

    public static boolean keyRingContainsKeyWithId( PGPPublicKeyRing ring,
                                                   long keyId) {
        return ring.getPublicKey(keyId) != null;
    }

    public static boolean keyRingContainsKeyWithId( PGPSecretKeyRing ring,
                                                   long keyId) {
        return ring.getSecretKey(keyId) != null;
    }
}
