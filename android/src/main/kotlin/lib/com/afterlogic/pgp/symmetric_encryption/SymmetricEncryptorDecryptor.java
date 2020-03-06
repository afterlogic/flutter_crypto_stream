
package lib.com.afterlogic.pgp.symmetric_encryption;



import lib.com.afterlogic.pgp.util.Passphrase;

import lib.org.bouncycastle.openpgp.PGPCompressedData;
import lib.org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import lib.org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import lib.org.bouncycastle.openpgp.PGPEncryptedDataList;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPLiteralData;
import lib.org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import lib.org.bouncycastle.openpgp.PGPPBEEncryptedData;
import lib.org.bouncycastle.openpgp.PGPUtil;
import lib.org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import lib.org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import lib.org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import lib.org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import lib.org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import lib.org.bouncycastle.util.io.Streams;
import lib.com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import lib.com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;


public class SymmetricEncryptorDecryptor {


    public static byte[] symmetricallyEncrypt( byte[] data,
                                               Passphrase password,
                                               SymmetricKeyAlgorithm encryptionAlgorithm,
                                               CompressionAlgorithm compressionAlgorithm)
            throws IOException, PGPException {

        byte[] compressedData = compress(data, compressionAlgorithm.getAlgorithmId());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(encryptionAlgorithm.getAlgorithmId())
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));

        encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(password.getChars()).setProvider("BC"));

        OutputStream encOut = encGen.open(bOut, compressedData.length);

        encOut.write(compressedData);
        encOut.close();

        return bOut.toByteArray();
    }


    public static byte[] symmetricallyDecrypt( byte[] data,  Passphrase password)
            throws IOException, PGPException {
        PGPPBEEncryptedData pbe;
        ByteArrayOutputStream outputStream = null;
        BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(data));
        InputStream in = PGPUtil.getDecoderStream(bis);

        try {
            BcPGPObjectFactory pgpF = new BcPGPObjectFactory(in);
            PGPEncryptedDataList enc;
            Object o = pgpF.nextObject();

            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            pbe = (PGPPBEEncryptedData) enc.get(0);

            InputStream clear = pbe.getDataStream(
                    new BcPBEDataDecryptorFactory(password.getChars(), new BcPGPDigestCalculatorProvider()));

            BcPGPObjectFactory pgpFact = new BcPGPObjectFactory(clear);

            o = pgpFact.nextObject();
            if (o instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) o;
                pgpFact = new BcPGPObjectFactory(cData.getDataStream());
                o = pgpFact.nextObject();
            }

            PGPLiteralData ld = (PGPLiteralData) o;
            InputStream unc = ld.getInputStream();

            try {
                outputStream = new ByteArrayOutputStream();

                Streams.pipeAll(unc, outputStream);
            } finally {
                if (outputStream != null) {
                    outputStream.close();
                }
            }
        } finally {
            in.close();
        }

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                throw new PGPException("Integrity check failed.");
            }
        } else {
            throw new PGPException("Symmetrically encrypted data is not integrity protected.");
        }

        return outputStream.toByteArray();
    }


    private static byte[] compress( byte[] clearData, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        OutputStream cos = comData.open(bOut);

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream  pOut = lData.open(cos,
                PGPLiteralData.BINARY,
                PGPLiteralDataGenerator.CONSOLE,
                clearData.length,
                new Date()
        );

        pOut.write(clearData);
        pOut.close();

        comData.close();

        return bOut.toByteArray();
    }

}
