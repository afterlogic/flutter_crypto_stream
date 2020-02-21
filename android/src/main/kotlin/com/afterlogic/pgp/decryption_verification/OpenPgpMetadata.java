
package com.afterlogic.pgp.decryption_verification;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;
import com.afterlogic.pgp.key.OpenPgpV4Fingerprint;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class OpenPgpMetadata {

    private final Set<Long> recipientKeyIds;
    private final OpenPgpV4Fingerprint decryptionFingerprint;
    private final Set<Long> unverifiedSignatureKeyIds;
    private final Set<OpenPgpV4Fingerprint> verifiedSignaturesFingerprints;

    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final boolean integrityProtected;

    public OpenPgpMetadata(Set<Long> recipientKeyIds,
                           OpenPgpV4Fingerprint decryptionFingerprint,
                           SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                           CompressionAlgorithm algorithm,
                           boolean integrityProtected,
                           Set<Long> unverifiedSignatureKeyIds,
                           Set<OpenPgpV4Fingerprint> verifiedSignaturesFingerprints) {

        this.recipientKeyIds = Collections.unmodifiableSet(recipientKeyIds);
        this.decryptionFingerprint = decryptionFingerprint;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.compressionAlgorithm = algorithm;
        this.integrityProtected = integrityProtected;
        this.unverifiedSignatureKeyIds = Collections.unmodifiableSet(unverifiedSignatureKeyIds);
        this.verifiedSignaturesFingerprints = Collections.unmodifiableSet(verifiedSignaturesFingerprints);
    }

    public Set<Long> getRecipientKeyIds() {
        return recipientKeyIds;
    }

    public boolean isEncrypted() {
        return !getRecipientKeyIds().isEmpty();
    }

    public OpenPgpV4Fingerprint getDecryptionFingerprint() {
        return decryptionFingerprint;
    }

    public SymmetricKeyAlgorithm getSymmetricKeyAlgorithm() {
        return symmetricKeyAlgorithm;
    }

    public CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public boolean isIntegrityProtected() {
        return integrityProtected;
    }

    public Set<Long> getAllSignatureKeyFingerprints() {
        return unverifiedSignatureKeyIds;
    }

    public boolean isSigned() {
        return !unverifiedSignatureKeyIds.isEmpty();
    }

    public Set<OpenPgpV4Fingerprint> getVerifiedSignaturesFingerprints() {
        return verifiedSignaturesFingerprints;
    }

    public boolean isVerified() {
        return !verifiedSignaturesFingerprints.isEmpty();
    }

    public boolean containsVerifiedSignatureFrom(PGPPublicKeyRing publicKeys) {
        for (PGPPublicKey key : publicKeys) {
            OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(key);
            if (containsVerifiedSignatureFrom(fingerprint)) {
                return true;
            }
        }
        return false;
    }

    public boolean containsVerifiedSignatureFrom(OpenPgpV4Fingerprint fingerprint) {
        return verifiedSignaturesFingerprints.contains(fingerprint);
    }

    static Builder getBuilder() {
        return new Builder();
    }

    static class Builder {

        private final Set<Long> recipientFingerprints = new HashSet<>();
        private OpenPgpV4Fingerprint decryptionFingerprint;
        private final Set<Long> unverifiedSignatureKeyIds = new HashSet<>();
        private final Set<OpenPgpV4Fingerprint> verifiedSignatureFingerprints = new HashSet<>();
        private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.NULL;
        private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
        private boolean integrityProtected = false;

        public Builder addRecipientKeyId(Long keyId) {
            this.recipientFingerprints.add(keyId);
            return this;
        }

        public Builder setDecryptionFingerprint(OpenPgpV4Fingerprint fingerprint) {
            this.decryptionFingerprint = fingerprint;
            return this;
        }

        public Builder setCompressionAlgorithm(CompressionAlgorithm algorithm) {
            this.compressionAlgorithm = algorithm;
            return this;
        }

        public Builder addUnverifiedSignatureKeyId(Long keyId) {
            this.unverifiedSignatureKeyIds.add(keyId);
            return this;
        }

        public Builder addVerifiedSignatureFingerprint(OpenPgpV4Fingerprint fingerprint) {
            this.verifiedSignatureFingerprints.add(fingerprint);
            return this;
        }

        public Builder setSymmetricKeyAlgorithm(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
            this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            return this;
        }

        public Builder setIntegrityProtected(boolean integrityProtected) {
            this.integrityProtected = integrityProtected;
            return this;
        }

        public OpenPgpMetadata build() {
            return new OpenPgpMetadata(recipientFingerprints, decryptionFingerprint, symmetricKeyAlgorithm, compressionAlgorithm, integrityProtected, unverifiedSignatureKeyIds, verifiedSignatureFingerprints);
        }
    }
}
