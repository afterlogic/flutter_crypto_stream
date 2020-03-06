package lib.com.afterlogic.pgp.encryption_signing;


import lib.com.afterlogic.pgp.algorithm.HashAlgorithmUtil;
import lib.org.bouncycastle.bcpg.ArmoredOutputStream;
import lib.org.bouncycastle.bcpg.BCPGOutputStream;
import lib.org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import lib.org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPLiteralData;
import lib.org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import lib.org.bouncycastle.openpgp.PGPPrivateKey;
import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPSignature;
import lib.org.bouncycastle.openpgp.PGPSignatureGenerator;
import lib.org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import lib.org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import lib.org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import lib.com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import lib.com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;
import lib.com.afterlogic.pgp.decryption_verification.OpenPgpMetadata;
import lib.com.afterlogic.pgp.key.OpenPgpV4Fingerprint;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class EncryptionStream extends OutputStream {

    private static final Logger LOGGER = Logger.getLogger(EncryptionStream.class.getName());
    private static final Level LEVEL = Level.FINE;

    private static final int BUFFER_SIZE = 1 << 8;

    private final OpenPgpMetadata result;

    private List<PGPSignatureGenerator> signatureGenerators = new ArrayList<>();
    private boolean closed = false;

    private ArmoredOutputStream armorOutputStream = null;

    private OutputStream publicKeyEncryptedStream = null;

    private PGPCompressedDataGenerator compressedDataGenerator;
    private BCPGOutputStream basicCompressionStream;

    private PGPLiteralDataGenerator literalDataGenerator;
    private OutputStream literalDataStream;

    EncryptionStream(OutputStream targetOutputStream,
                     Set<PGPPublicKey> encryptionKeys,
                     Set<PGPPrivateKey> signingKeys,
                     SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                     HashAlgorithmUtil hashAlgorithmUtil,
                     CompressionAlgorithm compressionAlgorithm,
                     boolean asciiArmor)
            throws IOException, PGPException {

        OutputStream outerMostStream;
        if (asciiArmor) {
            LOGGER.log(LEVEL, "Wrap encryption inputStream in ASCII armor");
            armorOutputStream = new ArmoredOutputStream(targetOutputStream);
            outerMostStream = armorOutputStream;
        } else {
            LOGGER.log(LEVEL, "Encryption inputStream will be binary");
            outerMostStream = targetOutputStream;
        }

        if (!encryptionKeys.isEmpty()) {
            LOGGER.log(LEVEL, "At least one encryption key is available -> encrypt using " + symmetricKeyAlgorithm);
            BcPGPDataEncryptorBuilder dataEncryptorBuilder =
                    new BcPGPDataEncryptorBuilder(symmetricKeyAlgorithm.getAlgorithmId());

            LOGGER.log(LEVEL, "Integrity protection enabled");
            dataEncryptorBuilder.setWithIntegrityPacket(true);

            PGPEncryptedDataGenerator encryptedDataGenerator =
                    new PGPEncryptedDataGenerator(dataEncryptorBuilder);

            for (PGPPublicKey key : encryptionKeys) {
                LOGGER.log(LEVEL, "Encrypt for key " + Long.toHexString(key.getKeyID()));
                encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(key));
            }

            publicKeyEncryptedStream = encryptedDataGenerator.open(outerMostStream, new byte[BUFFER_SIZE]);
            outerMostStream = publicKeyEncryptedStream;
        }

        if (!signingKeys.isEmpty()) {
            LOGGER.log(LEVEL, "At least one signing key is available -> addSignature " + hashAlgorithmUtil + " hash of message");
            for (PGPPrivateKey privateKey : signingKeys) {
                LOGGER.log(LEVEL, "Sign using key " + Long.toHexString(privateKey.getKeyID()));
                BcPGPContentSignerBuilder contentSignerBuilder = new BcPGPContentSignerBuilder(
                        privateKey.getPublicKeyPacket().getAlgorithm(), hashAlgorithmUtil.getAlgorithmId());


                PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
                signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);
                signatureGenerators.add(signatureGenerator);
            }
        }

        LOGGER.log(LEVEL, "Compress using " + compressionAlgorithm);
        compressedDataGenerator = new PGPCompressedDataGenerator(
                compressionAlgorithm.getAlgorithmId());
        basicCompressionStream = new BCPGOutputStream(compressedDataGenerator.open(outerMostStream));

        for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
            signatureGenerator.generateOnePassVersion(false).encode(basicCompressionStream);
        }

        literalDataGenerator = new PGPLiteralDataGenerator();
        literalDataStream = literalDataGenerator.open(basicCompressionStream,
                PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, new Date(), new byte[BUFFER_SIZE]);

        Set<Long> recipientKeyIds = new HashSet<>();
        for (PGPPublicKey recipient : encryptionKeys) {
            recipientKeyIds.add(recipient.getKeyID());
        }

        Set<Long> signingKeyIds = new HashSet<>();
        for (PGPPrivateKey signer : signingKeys) {
            signingKeyIds.add(signer.getKeyID());
        }


        this.result = new OpenPgpMetadata(recipientKeyIds,
                null, symmetricKeyAlgorithm,
                compressionAlgorithm, true,
                signingKeyIds, Collections.<OpenPgpV4Fingerprint>emptySet());
    }

    @Override
    public void write(int data) throws IOException {
        literalDataStream.write(data);

        for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
            byte asByte = (byte) (data & 0xff);
            signatureGenerator.update(asByte);
        }
    }

    @Override
    public void write(byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }


    @Override
    public void write(byte[] buffer, int off, int len) throws IOException {
        literalDataStream.write(buffer, 0, len);
        for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
            signatureGenerator.update(buffer, 0, len);
        }
    }

    @Override
    public void flush() throws IOException {
        literalDataStream.flush();
    }

    @Override
    public void close() throws IOException {
        if (!closed) {

            literalDataStream.flush();
            literalDataStream.close();
            literalDataGenerator.close();

            for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
                try {
                    signatureGenerator.generate().encode(basicCompressionStream);
                } catch (PGPException e) {
                    throw new IOException(e);
                }
            }

            compressedDataGenerator.close();

            if (publicKeyEncryptedStream != null) {
                publicKeyEncryptedStream.flush();
                publicKeyEncryptedStream.close();
            }

            if (armorOutputStream != null) {
                armorOutputStream.flush();
                armorOutputStream.close();
            }
            closed = true;
        }
    }

    public OpenPgpMetadata getResult() {
        return result;
    }
}
