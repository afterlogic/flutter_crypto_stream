
package lib.com.afterlogic.pgp.encryption_signing;


import lib.com.afterlogic.pgp.algorithm.HashAlgorithmUtil;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPrivateKey;
import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKey;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import lib.com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import lib.com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;
import lib.com.afterlogic.pgp.key.protection.SecretKeyRingProtector;
import lib.com.afterlogic.pgp.key.selection.key.PublicKeySelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.key.SecretKeySelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.key.impl.EncryptionKeySelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.key.impl.NoRevocation;
import lib.com.afterlogic.pgp.key.selection.key.impl.SignatureKeySelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.key.util.And;
import lib.com.afterlogic.pgp.key.selection.keyring.PublicKeyRingSelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.keyring.SecretKeyRingSelectionStrategy;
import lib.com.afterlogic.pgp.util.MultiMap;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class EncryptionBuilder implements EncryptionBuilderInterface {

    private OutputStream outputStream;
    private final Set<PGPPublicKey> encryptionKeys = new HashSet<>();
    private final Set<PGPSecretKey> signingKeys = new HashSet<>();
    private SecretKeyRingProtector signingKeysDecryptor;
    private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_128;
    private HashAlgorithmUtil hashAlgorithmUtil = HashAlgorithmUtil.SHA256;
    private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
    private boolean asciiArmor = false;

    @Override
    public ToRecipients onOutputStream(OutputStream outputStream) {
        this.outputStream = outputStream;
        return new ToRecipientsImpl();
    }

    class ToRecipientsImpl implements ToRecipients {

        @Override
        public WithAlgorithms toRecipients() {
            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(PGPPublicKey... keys) {
            for (PGPPublicKey k : keys) {
                if (encryptionKeySelector().accept(null, k)) {
                    EncryptionBuilder.this.encryptionKeys.add(k);
                } else {
                    throw new IllegalArgumentException("Key " + k.getKeyID() + " is not a valid encryption key.");
                }
            }

            if (EncryptionBuilder.this.encryptionKeys.isEmpty()) {
                throw new IllegalStateException("No valid encryption keys found!");
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(PGPPublicKeyRing... keys) {
            for (PGPPublicKeyRing ring : keys) {
                for (PGPPublicKey k : ring) {
                    if (encryptionKeySelector().accept(null, k)) {
                        EncryptionBuilder.this.encryptionKeys.add(k);
                    }
                }
            }

            if (EncryptionBuilder.this.encryptionKeys.isEmpty()) {
                throw new IllegalStateException("No valid encryption keys found!");
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(PGPPublicKeyRingCollection... keys) {
            for (PGPPublicKeyRingCollection collection : keys) {
                for (PGPPublicKeyRing ring : collection) {
                    for (PGPPublicKey k : ring) {
                        if (encryptionKeySelector().accept(null, k)) {
                            EncryptionBuilder.this.encryptionKeys.add(k);
                        }
                    }
                }
            }

            if (EncryptionBuilder.this.encryptionKeys.isEmpty()) {
                throw new IllegalStateException("No valid encryption keys found!");
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public <O> WithAlgorithms toRecipients(PublicKeyRingSelectionStrategy<O> ringSelectionStrategy,
                                               MultiMap<O, PGPPublicKeyRingCollection> keys) {
            if (keys.isEmpty()) {
                throw new IllegalArgumentException("Recipient map MUST NOT be empty.");
            }
            MultiMap<O, PGPPublicKeyRing> acceptedKeyRings = ringSelectionStrategy.selectKeyRingsFromCollections(keys);
            for (O identifier : acceptedKeyRings.keySet()) {
                Set<PGPPublicKeyRing> acceptedSet = acceptedKeyRings.get(identifier);
                for (PGPPublicKeyRing ring : acceptedSet) {
                    for (PGPPublicKey k : ring) {
                        if (encryptionKeySelector().accept(null, k)) {
                            EncryptionBuilder.this.encryptionKeys.add(k);
                        }
                    }
                }
            }

            if (EncryptionBuilder.this.encryptionKeys.isEmpty()) {
                throw new IllegalStateException("No valid encryption keys found!");
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public SignWith doNotEncrypt() {
            return new SignWithImpl();
        }
    }

    class WithAlgorithmsImpl implements WithAlgorithms {

        @Override
        public WithAlgorithms andToSelf(PGPPublicKey... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPPublicKey k : keys) {
                if (encryptionKeySelector().accept(null, k)) {
                    EncryptionBuilder.this.encryptionKeys.add(k);
                } else {
                    throw new IllegalArgumentException("Key " + k.getKeyID() + " is not a valid encryption key.");
                }
            }
            return this;
        }

        @Override
        public WithAlgorithms andToSelf(PGPPublicKeyRing... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPPublicKeyRing ring : keys) {
                for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
                    PGPPublicKey key = i.next();
                    if (encryptionKeySelector().accept(null, key)) {
                        EncryptionBuilder.this.encryptionKeys.add(key);
                    }
                }
            }
            return this;
        }

        @Override
        public WithAlgorithms andToSelf(PGPPublicKeyRingCollection keys) {
            for (PGPPublicKeyRing ring : keys) {
                for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
                    PGPPublicKey key = i.next();
                    if (encryptionKeySelector().accept(null, key)) {
                        EncryptionBuilder.this.encryptionKeys.add(key);
                    }
                }
            }
            return this;
        }

        @Override
        public <O> WithAlgorithms andToSelf(PublicKeyRingSelectionStrategy<O> ringSelectionStrategy,
                                            MultiMap<O, PGPPublicKeyRingCollection> keys) {
            if (keys.isEmpty()) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            MultiMap<O, PGPPublicKeyRing> acceptedKeyRings =
                    ringSelectionStrategy.selectKeyRingsFromCollections(keys);
            for (O identifier : acceptedKeyRings.keySet()) {
                Set<PGPPublicKeyRing> acceptedSet = acceptedKeyRings.get(identifier);
                for (PGPPublicKeyRing k : acceptedSet) {
                    for (Iterator<PGPPublicKey> i = k.getPublicKeys(); i.hasNext(); ) {
                        PGPPublicKey key = i.next();
                        if (encryptionKeySelector().accept(null, key)) {
                            EncryptionBuilder.this.encryptionKeys.add(key);
                        }
                    }
                }
            }
            return this;
        }

        @Override
        public SignWith usingAlgorithms(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                        HashAlgorithmUtil hashAlgorithmUtil,
                                        CompressionAlgorithm compressionAlgorithm) {

            EncryptionBuilder.this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            EncryptionBuilder.this.hashAlgorithmUtil = hashAlgorithmUtil;
            EncryptionBuilder.this.compressionAlgorithm = compressionAlgorithm;

            return new SignWithImpl();
        }

        @Override
        public SignWith usingSecureAlgorithms() {
            EncryptionBuilder.this.symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_256;
            EncryptionBuilder.this.hashAlgorithmUtil = HashAlgorithmUtil.SHA512;
            EncryptionBuilder.this.compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;

            return new SignWithImpl();
        }
    }

    class SignWithImpl implements SignWith {

        @Override
        public <O> Armor signWith(SecretKeyRingProtector decryptor,
                                  PGPSecretKey... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPSecretKey s : keys) {
                if (EncryptionBuilder.this.<O>signingKeySelector().accept(null, s)) {
                    signingKeys.add(s);
                } else {
                    throw new IllegalArgumentException("Key " + s.getKeyID() + " is not a valid signing key.");
                }
            }
            EncryptionBuilder.this.signingKeysDecryptor = decryptor;
            return new ArmorImpl();
        }

        @Override
        public <O> Armor signWith(SecretKeyRingProtector decryptor,
                                  PGPSecretKeyRing... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPSecretKeyRing key : keys) {
                for (Iterator<PGPSecretKey> i = key.getSecretKeys(); i.hasNext(); ) {
                    PGPSecretKey s = i.next();
                    if (EncryptionBuilder.this.<O>signingKeySelector().accept(null, s)) {
                        EncryptionBuilder.this.signingKeys.add(s);
                    }
                }
            }
            EncryptionBuilder.this.signingKeysDecryptor = decryptor;
            return new ArmorImpl();
        }

        @Override
        public <O> Armor signWith(SecretKeyRingSelectionStrategy<O> ringSelectionStrategy,
                                  SecretKeyRingProtector decryptor,
                                  MultiMap<O, PGPSecretKeyRingCollection> keys) {
            if (keys.isEmpty()) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            MultiMap<O, PGPSecretKeyRing> acceptedKeyRings =
                    ringSelectionStrategy.selectKeyRingsFromCollections(keys);
            for (O identifier : acceptedKeyRings.keySet()) {
                Set<PGPSecretKeyRing> acceptedSet = acceptedKeyRings.get(identifier);
                for (PGPSecretKeyRing k : acceptedSet) {
                    for (Iterator<PGPSecretKey> i = k.getSecretKeys(); i.hasNext(); ) {
                        PGPSecretKey s = i.next();
                        if (EncryptionBuilder.this.<O>signingKeySelector().accept(null, s)) {
                            EncryptionBuilder.this.signingKeys.add(s);
                        }
                    }
                }
            }
            return new ArmorImpl();
        }

        @Override
        public Armor doNotSign() {
            return new ArmorImpl();
        }
    }

    class ArmorImpl implements Armor {

        @Override
        public EncryptionStream asciiArmor() throws IOException, PGPException {
            EncryptionBuilder.this.asciiArmor = true;
            return build();
        }

        @Override
        public EncryptionStream noArmor() throws IOException, PGPException {
            EncryptionBuilder.this.asciiArmor = false;
            return build();
        }

        private EncryptionStream build() throws IOException, PGPException {

            Set<PGPPrivateKey> privateKeys = new HashSet<>();
            for (PGPSecretKey secretKey : signingKeys) {
                privateKeys.add(secretKey.extractPrivateKey(signingKeysDecryptor.getDecryptor(secretKey.getKeyID())));
            }

            return new EncryptionStream(
                    EncryptionBuilder.this.outputStream,
                    EncryptionBuilder.this.encryptionKeys,
                    privateKeys,
                    EncryptionBuilder.this.symmetricKeyAlgorithm,
                    EncryptionBuilder.this.hashAlgorithmUtil,
                    EncryptionBuilder.this.compressionAlgorithm,
                    EncryptionBuilder.this.asciiArmor);
        }
    }

    <O> PublicKeySelectionStrategy<O> encryptionKeySelector() {
        return new And.PubKeySelectionStrategy<>(
                new NoRevocation.PubKeySelectionStrategy<O>(),
                new EncryptionKeySelectionStrategy<O>());
    }

    <O> SecretKeySelectionStrategy<O> signingKeySelector() {
        return new And.SecKeySelectionStrategy<O>(
                new NoRevocation.SecKeySelectionStrategy<O>(),
                new SignatureKeySelectionStrategy<O>());
    }
}
