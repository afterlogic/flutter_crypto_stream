package lib.com.afterlogic.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import lib.com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import lib.com.afterlogic.pgp.algorithm.HashAlgorithmUtil;
import lib.com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;
import lib.com.afterlogic.pgp.decryption_verification.DecryptionBuilder;
import lib.com.afterlogic.pgp.decryption_verification.DecryptionBuilderInterface;
import lib.com.afterlogic.pgp.decryption_verification.MissingPublicKeyCallback;
import lib.com.afterlogic.pgp.encryption_signing.EncryptionBuilder;
import lib.com.afterlogic.pgp.encryption_signing.EncryptionBuilderInterface;
import lib.com.afterlogic.pgp.key.parsing.KeyRingReader;
import lib.com.afterlogic.pgp.key.protection.KeyRingProtectionSettings;
import lib.com.afterlogic.pgp.key.protection.PasswordBasedSecretKeyRingProtector;
import lib.com.afterlogic.pgp.key.protection.SecretKeyPassphraseProvider;
import lib.com.afterlogic.pgp.util.NewPGPUtil;
import lib.com.afterlogic.pgp.util.Passphrase;
import lib.org.bouncycastle.bcpg.ArmoredOutputStream;
import lib.org.bouncycastle.bcpg.BCPGOutputStream;
import lib.org.bouncycastle.bcpg.HashAlgorithmTags;
import lib.org.bouncycastle.openpgp.PGPCompressedData;
import lib.org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import lib.org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import lib.org.bouncycastle.openpgp.PGPEncryptedDataList;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPLiteralData;
import lib.org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import lib.org.bouncycastle.openpgp.PGPPBEEncryptedData;
import lib.org.bouncycastle.openpgp.PGPPrivateKey;
import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKey;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSignature;
import lib.org.bouncycastle.openpgp.PGPSignatureGenerator;
import lib.org.bouncycastle.openpgp.PGPSignatureList;
import lib.org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import lib.org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import lib.org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import lib.org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import lib.org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import lib.org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import lib.org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import lib.org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import lib.org.bouncycastle.util.io.Streams;

public class PgpApi {
    public boolean lastVerifyResult = true;
    final BcPGPDigestCalculatorProvider digestCalculator = new BcPGPDigestCalculatorProvider();

    public boolean getLastVerifyResult() {
        return lastVerifyResult;
    }

    public void encrypt(
            String privateKey,
            String[] publicKeys,
            final String password,
            InputStream inputStream,
            OutputStream outputStream) throws IOException, PGPException, PgpError {

        try {
            EncryptionBuilderInterface.ToRecipients toRecipients = new EncryptionBuilder().onOutputStream(outputStream);

            EncryptionBuilderInterface.SignWith signWith = toRecipients.toRecipients(PgpUtilApi.getPublicKeyRing(publicKeys))
                    .usingAlgorithms(
                            SymmetricKeyAlgorithm.AES_256,
                            HashAlgorithmUtil.SHA512,
                            CompressionAlgorithm.ZIP
                    );

            EncryptionBuilderInterface.Armor armor;
            if (privateKey != null && password != null) {
                KeyRingProtectionSettings setting = new KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithmUtil.MD5, 0);
                PGPSecretKeyRing secretKeysRing = new KeyRingReader().secretKeyRing(privateKey);
                PGPSecretKey secretKey = null;
                for (PGPSecretKey key : secretKeysRing) {
                    if (secretKey == null || key.isMasterKey()) {
                        secretKey = key;
                    }
                }
                PasswordBasedSecretKeyRingProtector secretKeyRingProtector = new PasswordBasedSecretKeyRingProtector(setting, new SecretKeyPassphraseProvider() {
                    @Override
                    public Passphrase getPassphraseFor(Long keyId) {
                        return new Passphrase(password.toCharArray());
                    }
                });

                armor = signWith.signWith(secretKeyRingProtector, secretKey);
            } else {
                armor = signWith.doNotSign();
            }

            OutputStream encryptionStream = armor.asciiArmor();

            byte[] bs = new byte[4096];
            int numRead;

            while ((numRead = inputStream.read(bs, 0, bs.length)) >= 0) {
                encryptionStream.write(bs, 0, numRead);
            }

            encryptionStream.close();
            inputStream.close();
            outputStream.close();
        } catch (Throwable e) {
            if (e instanceof PgpError) {
                throw (PgpError) e;
            } else {
                throw new PgpError(PgpErrorCase.Undefined);
            }
        }
    }

    public void decrypt(String privateKey,
                        String[] publicKeys,
                        final String password,
                        InputStream inputStream,
                        OutputStream outputStream) throws IOException, PGPException, PgpError {
        try {
            lastVerifyResult = true;

            DecryptionBuilderInterface.DecryptWith decryptWith = new DecryptionBuilder().onInputStream(inputStream);

            KeyRingProtectionSettings setting = new KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithmUtil.MD5, 0);
            PGPSecretKeyRing secretKeys = new KeyRingReader().secretKeyRing(privateKey);
            PasswordBasedSecretKeyRingProtector secretKeyRingProtector = new PasswordBasedSecretKeyRingProtector(setting, new SecretKeyPassphraseProvider() {
                @Override
                public Passphrase getPassphraseFor(Long keyId) {
                    return new Passphrase(password.toCharArray());
                }
            });

            PGPSecretKeyRingCollection secretKeyRings = NewPGPUtil.keyRingsToKeyRingCollection(secretKeys);

            DecryptionBuilderInterface.VerifyWith verifyWith = decryptWith.decryptWith(
                    secretKeyRingProtector,
                    secretKeyRings
            );

            DecryptionBuilderInterface.Build build;


            build = verifyWith.verifyWith(PgpUtilApi.getPublicKeyRing(publicKeys))
                    .handleMissingPublicKeysWith(new MissingPublicKeyCallback() {
                        @Override
                        public PGPPublicKey onMissingPublicKeyEncountered(Long keyId) {
                            lastVerifyResult = false;
                            return null;
                        }
                    });

            InputStream decryptionStream = build.build();
            Streams.pipeAll(decryptionStream, outputStream);
            decryptionStream.close();
            inputStream.close();
            outputStream.close();
        } catch (Throwable e) {
            if (e instanceof PgpError) {
                throw (PgpError) e;
            } else {
                throw new PgpError(PgpErrorCase.Undefined);
            }
        }
    }

    public String sign(String text, String privateKey, final String password) throws PgpError {
        try {

            ByteArrayOutputStream output = new ByteArrayOutputStream();
            InputStream input = new ByteArrayInputStream(text.getBytes());
            KeyRingProtectionSettings setting = new KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithmUtil.MD5, 0);
            PGPSecretKeyRing secretKeysRing = new KeyRingReader().secretKeyRing(privateKey);
            PasswordBasedSecretKeyRingProtector secretKeyRingProtector = new PasswordBasedSecretKeyRingProtector(setting, new SecretKeyPassphraseProvider() {
                @Override
                public Passphrase getPassphraseFor(Long keyId) {
                    return new Passphrase(password.toCharArray());
                }
            });
            PGPSecretKey secretKey = null;
            for (PGPSecretKey key : secretKeysRing) {
                if (secretKey == null || key.isMasterKey()) {
                    secretKey = key;
                }
            }

            PGPPrivateKey pgpPrivateKey =secretKey.extractPrivateKey(secretKeyRingProtector.getDecryptor(secretKey.getKeyID()));

            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                    new BcPGPContentSignerBuilder(
                            pgpPrivateKey.getPublicKeyPacket().getAlgorithm(),
                            HashAlgorithmTags.SHA512
                    )
            );
            signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivateKey);
            OutputStream armor = new ArmoredOutputStream(output);
            OutputStream stream = new BCPGOutputStream(armor);


            byte[] buff = new byte[1024];
            int read;
            while ((read = input.read(buff)) != -1) {
                signatureGenerator.update(buff, 0, read);
            }
            signatureGenerator.generate().encode(stream);

            armor.close();
            stream.close();
            output.close();
            input.close();

            String signature = new String(output.toByteArray());
            return PGP_SIGN_TITLE + "\r\n" +
                    "Hash: SHA256\r\n\r\n" +
                    text + "\r\n" +
                    signature;
        } catch (Throwable e) {
            if (e instanceof PgpError) {
                throw (PgpError) e;
            } else {
                throw new PgpError(PgpErrorCase.Undefined);
            }
        }
    }

    @SuppressWarnings("ConstantConditions")
    public String verify(String text, String[] publicKeys) throws PgpError {
        try {
            lastVerifyResult = false;

            int startMessageIndex = text.indexOf(PGP_SIGN_TITLE);
            if (startMessageIndex < 0) {
                return text;
            }

            startMessageIndex = text.indexOf("\n", startMessageIndex + PGP_SIGN_TITLE.length()) + 1;
            startMessageIndex = text.indexOf("\n", startMessageIndex) + 1;
            startMessageIndex = text.indexOf("\n", startMessageIndex) + 1;

            int startSignature = text.indexOf(BEGIN_SIGNATURE, startMessageIndex);
            if (startSignature < 0) {
                return text;
            }

            String message = text.substring(startMessageIndex, startSignature);

            int endMessageIndex = message.lastIndexOf("\n");
            if (message.charAt(endMessageIndex - 1) == '\r') {
                endMessageIndex = endMessageIndex - 1;
            }
            endMessageIndex += startMessageIndex;


            int endSignature = text.indexOf(END_SIGNATURE);
            if (endSignature < 0) {
                return text;
            }
            endSignature += END_SIGNATURE.length();

            message = text.substring(startMessageIndex, endMessageIndex);
            ByteArrayInputStream signedDataStream = new ByteArrayInputStream(message.getBytes());
            ByteArrayInputStream signature = new ByteArrayInputStream(text.substring(startSignature, endSignature).getBytes());


            try {
                InputStream decoderStream = lib.org.bouncycastle.openpgp.PGPUtil.getDecoderStream(signature);

                PGPPublicKeyRingCollection pgpPublicKeyRingCollection = PgpUtilApi.getPublicKeyRing(publicKeys);

                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(decoderStream);
                PGPSignatureList signatureList = ((PGPSignatureList) pgpFact.nextObject());
                PGPSignature pgpSignature = null;
                for (PGPSignature item : signatureList) {
                    if (pgpPublicKeyRingCollection.contains(item.getKeyID())) {
                        pgpSignature = item;
                        break;
                    }
                }
                if (pgpSignature == null) {
                    return message;
                }

                PGPPublicKey key = pgpPublicKeyRingCollection.getPublicKey(pgpSignature.getKeyID());

                pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), key);

                byte[] buff = new byte[1024];
                int read;
                while ((read = signedDataStream.read(buff)) != -1) {
                    pgpSignature.update(buff, 0, read);
                }
                signedDataStream.close();
                lastVerifyResult = pgpSignature.verify();

            } catch (Throwable e) {
                e.printStackTrace();
            }
            return message;
        } catch (Throwable e) {
            if (e instanceof PgpError) {
                throw (PgpError) e;
            } else {
                throw new PgpError(PgpErrorCase.Undefined);
            }
        }

    }

    public void symmetricallyEncrypt(InputStream inputStream,
                                     OutputStream outputStream,
                                     File prepareEncrypt,
                                     Long length,
                                     String password) throws PgpError {
        try {

            SymmetricKeyAlgorithm encryptionAlgorithm = SymmetricKeyAlgorithm.AES_256;
            CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.ZIP;
            OutputStream armorOut = new ArmoredOutputStream(outputStream);
            Passphrase passphrase = new Passphrase(password.toCharArray());

            compress(inputStream, new FileOutputStream(prepareEncrypt), compressionAlgorithm.getAlgorithmId(), length);
            InputStream preparedInputStream = new FileInputStream(prepareEncrypt);

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(encryptionAlgorithm.getAlgorithmId())
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
            );

            encGen.addMethod(
                    new BcPBEKeyEncryptionMethodGenerator(passphrase.getChars())
                            .setSecureRandom(new SecureRandom())
            );

            OutputStream encOut = encGen.open(armorOut, prepareEncrypt.length());

            Streams.pipeAll(preparedInputStream, encOut);

            encOut.close();

            //noinspection ResultOfMethodCallIgnored
            prepareEncrypt.delete();
            encOut.close();
            preparedInputStream.close();
            inputStream.close();
            armorOut.close();
            outputStream.close();
        } catch (Throwable e) {
            if (e instanceof PgpError) {
                throw (PgpError) e;
            } else {
                throw new PgpError(PgpErrorCase.Undefined);
            }
        }
    }

    private void compress(InputStream inputStream, OutputStream outputStream, int algorithm, long size) throws IOException {
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        OutputStream cos = comData.open(outputStream);

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(cos,
                PGPLiteralData.BINARY,
                PGPLiteralDataGenerator.CONSOLE,
                size,
                new Date()
        );
        Streams.pipeAll(inputStream, pOut);
        pOut.close();

        comData.close();
    }

    public void symmetricallyDecrypt(InputStream inputStream, OutputStream outputStream, String password) throws IOException, PGPException, PgpError {
        try {
            lastVerifyResult = false;
            Passphrase passphrase = new Passphrase(password.toCharArray());
            PGPPBEEncryptedData pbe;

            InputStream decoderInput = lib.org.bouncycastle.openpgp.PGPUtil.getDecoderStream(inputStream);

            BcPGPObjectFactory pgpF = new BcPGPObjectFactory(decoderInput);
            PGPEncryptedDataList enc;
            Object o = pgpF.nextObject();

            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            pbe = (PGPPBEEncryptedData) enc.get(0);

            InputStream clear = pbe.getDataStream(
                    new BcPBEDataDecryptorFactory(passphrase.getChars(), digestCalculator));

            BcPGPObjectFactory pgpFact = new BcPGPObjectFactory(clear);

            o = pgpFact.nextObject();
            if (o instanceof PGPCompressedData) {
                pgpFact = new BcPGPObjectFactory(((PGPCompressedData) o).getDataStream());
                o = pgpFact.nextObject();
            }

            PGPLiteralData ld = (PGPLiteralData) o;
            InputStream unc = ld.getInputStream();

            Streams.pipeAll(unc, outputStream);

            outputStream.close();
            decoderInput.close();

            lastVerifyResult = pbe.verify();
        } catch (Throwable e) {
            if (e instanceof PgpError) {
                throw (PgpError) e;
            } else {
                throw new PgpError(PgpErrorCase.Undefined);
            }
        }
    }

    private final String PGP_SIGN_TITLE = "-----BEGIN PGP SIGNED MESSAGE-----";
    private final String BEGIN_SIGNATURE = "-----BEGIN PGP SIGNATURE-----";
    private final String END_SIGNATURE = "-----END PGP SIGNATURE-----";
}
