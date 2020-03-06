
package lib.com.afterlogic.pgp.decryption_verification;


import lib.org.bouncycastle.openpgp.PGPCompressedData;
import lib.org.bouncycastle.openpgp.PGPEncryptedDataList;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPLiteralData;
import lib.org.bouncycastle.openpgp.PGPObjectFactory;
import lib.org.bouncycastle.openpgp.PGPOnePassSignature;
import lib.org.bouncycastle.openpgp.PGPOnePassSignatureList;
import lib.org.bouncycastle.openpgp.PGPPrivateKey;
import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKey;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPUtil;
import lib.org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import lib.org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import lib.org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import lib.org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import lib.org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import lib.org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import lib.com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import lib.com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;
import lib.com.afterlogic.pgp.key.OpenPgpV4Fingerprint;
import lib.com.afterlogic.pgp.key.protection.SecretKeyRingProtector;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class DecryptionStreamFactory {

    private static final Logger LOGGER = Logger.getLogger(DecryptionStreamFactory.class.getName());
    private static final Level LEVEL = Level.FINE;

    private final PGPSecretKeyRingCollection decryptionKeys;
    private final SecretKeyRingProtector decryptionKeyDecryptor;
    private final Set<PGPPublicKeyRing> verificationKeys = new HashSet<>();
    private final MissingPublicKeyCallback missingPublicKeyCallback;

    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
    private final PGPContentVerifierBuilderProvider verifierBuilderProvider = new BcPGPContentVerifierBuilderProvider();
    private final KeyFingerPrintCalculator fingerCalc = new BcKeyFingerprintCalculator();
    private final Map<OpenPgpV4Fingerprint, PGPOnePassSignature> verifiableOnePassSignatures = new HashMap<>();

    private DecryptionStreamFactory(PGPSecretKeyRingCollection decryptionKeys,
                                    SecretKeyRingProtector decryptor,
                                    Set<PGPPublicKeyRing> verificationKeys,
                                    MissingPublicKeyCallback missingPublicKeyCallback) {
        this.decryptionKeys = decryptionKeys;
        this.decryptionKeyDecryptor = decryptor;
        this.verificationKeys.addAll(verificationKeys != null ? verificationKeys : Collections.<PGPPublicKeyRing>emptyList());
        this.missingPublicKeyCallback = missingPublicKeyCallback;
    }

    public static DecryptionStream create(InputStream inputStream,
                                          PGPSecretKeyRingCollection decryptionKeys,
                                          SecretKeyRingProtector decryptor,
                                          Set<PGPPublicKeyRing> verificationKeys,
                                          MissingPublicKeyCallback missingPublicKeyCallback)
            throws IOException, PGPException {

        DecryptionStreamFactory factory = new DecryptionStreamFactory(decryptionKeys,
                decryptor,
                verificationKeys,
                missingPublicKeyCallback);

        PGPObjectFactory objectFactory = new PGPObjectFactory(
                PGPUtil.getDecoderStream(inputStream), new BcKeyFingerprintCalculator());

        return new DecryptionStream(factory.wrap(objectFactory), factory.resultBuilder);
    }

    private InputStream wrap(PGPObjectFactory objectFactory) throws IOException, PGPException {

        Object pgpObj;
        while ((pgpObj = objectFactory.nextObject()) != null) {

            if (pgpObj instanceof PGPEncryptedDataList) {
                LOGGER.log(LEVEL, "Encountered PGPEncryptedDataList");
                PGPEncryptedDataList encDataList = (PGPEncryptedDataList) pgpObj;
                InputStream nextStream = decrypt(encDataList);
                objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(nextStream), fingerCalc);
                return wrap(objectFactory);
            }

            if (pgpObj instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) pgpObj;
                InputStream nextStream = compressedData.getDataStream();
                resultBuilder.setCompressionAlgorithm(CompressionAlgorithm.fromId(compressedData.getAlgorithm()));
                objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(nextStream), fingerCalc);
                LOGGER.log(LEVEL, "Encountered PGPCompressedData: " +
                        CompressionAlgorithm.fromId(compressedData.getAlgorithm()));
                return wrap(objectFactory);
            }

            if (pgpObj instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) pgpObj;
                LOGGER.log(LEVEL, "Encountered PGPOnePassSignatureList of size " + onePassSignatures.size());
                initOnePassSignatures(onePassSignatures);
                return wrap(objectFactory);
            }

            if (pgpObj instanceof PGPLiteralData) {
                LOGGER.log(LEVEL, "Found PGPLiteralData");
                PGPLiteralData literalData = (PGPLiteralData) pgpObj;
                InputStream literalDataInputStream = literalData.getInputStream();

                if (verifiableOnePassSignatures.isEmpty()) {
                    LOGGER.log(LEVEL, "No OnePassSignatures found -> We are done");
                    return literalDataInputStream;
                }

                return new SignatureVerifyingInputStream(literalDataInputStream,
                        objectFactory, verifiableOnePassSignatures, resultBuilder);
            }
        }

        throw new PGPException("No Literal Data Packet found");
    }

    private InputStream decrypt(PGPEncryptedDataList encryptedDataList)
            throws PGPException {
        Iterator<?> iterator = encryptedDataList.getEncryptedDataObjects();
        if (!iterator.hasNext()) {
            throw new PGPException("Decryption failed - EncryptedDataList has no items");
        }

        PGPPrivateKey decryptionKey = null;
        PGPPublicKeyEncryptedData encryptedSessionKey = null;
        while (iterator.hasNext()) {
            PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) iterator.next();
            long keyId = encryptedData.getKeyID();

            resultBuilder.addRecipientKeyId(keyId);
            LOGGER.log(LEVEL, "PGPEncryptedData is encrypted for key " + Long.toHexString(keyId));

            PGPSecretKey secretKey = decryptionKeys.getSecretKey(keyId);
            if (secretKey != null) {
                LOGGER.log(LEVEL, "Found respective secret key " + Long.toHexString(keyId));
                encryptedSessionKey = encryptedData;
                decryptionKey = secretKey.extractPrivateKey(decryptionKeyDecryptor.getDecryptor(keyId));
                resultBuilder.setDecryptionFingerprint(new OpenPgpV4Fingerprint(secretKey));
            }
        }

        if (decryptionKey == null) {
            throw new PGPException("Decryption failed - No suitable decryption key found");
        }

        PublicKeyDataDecryptorFactory keyDecryptor = new BcPublicKeyDataDecryptorFactory(decryptionKey);
        SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm
                .fromId(encryptedSessionKey.getSymmetricAlgorithm(keyDecryptor));

        LOGGER.log(LEVEL, "Message is encrypted using " + symmetricKeyAlgorithm);
        resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);

        if (encryptedSessionKey.isIntegrityProtected()) {
            LOGGER.log(LEVEL, "Message is integrity protected");
            resultBuilder.setIntegrityProtected(true);
        } else {
            LOGGER.log(LEVEL, "Message is not integrity protected");
            resultBuilder.setIntegrityProtected(false);
        }
        InputStream decryptionStream = encryptedSessionKey.getDataStream(keyDecryptor);

        return decryptionStream;
    }

    private void initOnePassSignatures(PGPOnePassSignatureList onePassSignatureList) throws PGPException {
        Iterator<PGPOnePassSignature> iterator = onePassSignatureList.iterator();
        if (!iterator.hasNext()) {
            throw new PGPException("Verification failed - No OnePassSignatures found");
        }

        while (iterator.hasNext()) {
            PGPOnePassSignature signature = iterator.next();
            final long keyId = signature.getKeyID();
            resultBuilder.addUnverifiedSignatureKeyId(keyId);

            LOGGER.log(LEVEL, "Message contains OnePassSignature from " + Long.toHexString(keyId));

                        PGPPublicKey verificationKey = null;
            for (PGPPublicKeyRing publicKeyRing : verificationKeys) {
                verificationKey = publicKeyRing.getPublicKey(keyId);
                if (verificationKey != null) {
                    LOGGER.log(LEVEL, "Found respective public key " + Long.toHexString(keyId));
                    break;
                }
            }

            if (verificationKey == null) {
                LOGGER.log(Level.FINER, "No public key for signature of " + Long.toHexString(keyId) + " found.");

                if (missingPublicKeyCallback == null) {
                    LOGGER.log(Level.FINER, "Skip signature of " + Long.toHexString(keyId));
                    continue;
                }

                PGPPublicKey missingPublicKey = missingPublicKeyCallback.onMissingPublicKeyEncountered(keyId);
                if (missingPublicKey == null) {
                    LOGGER.log(Level.FINER, "Skip signature of " + Long.toHexString(keyId));
                    continue;
                }

                if (missingPublicKey.getKeyID() != keyId) {
                    throw new IllegalArgumentException("KeyID of the provided public key differs from the signatures keyId. " +
                            "The signature was created from " + Long.toHexString(keyId) + " while the provided key has ID " +
                            Long.toHexString(missingPublicKey.getKeyID()));
                }

                verificationKey = missingPublicKey;
            }

            signature.init(verifierBuilderProvider, verificationKey);
            verifiableOnePassSignatures.put(new OpenPgpV4Fingerprint(verificationKey), signature);
        }
    }
}
