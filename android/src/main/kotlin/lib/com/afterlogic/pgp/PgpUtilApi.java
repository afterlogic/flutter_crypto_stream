package lib.com.afterlogic.pgp;

import lib.com.afterlogic.pgp.algorithm.HashAlgorithm;
import lib.com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;
import lib.com.afterlogic.pgp.key.collection.PGPKeyRing;
import lib.com.afterlogic.pgp.key.generation.KeyRingBuilder;
import lib.com.afterlogic.pgp.key.generation.KeySpec;
import lib.com.afterlogic.pgp.key.generation.type.RSA_GENERAL;
import lib.com.afterlogic.pgp.key.generation.type.length.RsaLength;
import lib.com.afterlogic.pgp.key.parsing.KeyRingReader;
import lib.com.afterlogic.pgp.key.protection.KeyRingProtectionSettings;
import lib.com.afterlogic.pgp.key.protection.PasswordBasedSecretKeyRingProtector;
import lib.com.afterlogic.pgp.key.protection.SecretKeyPassphraseProvider;
import lib.com.afterlogic.pgp.util.Passphrase;

import lib.org.bouncycastle.bcpg.ArmoredOutputStream;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPrivateKey;
import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKey;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;
import lib.org.bouncycastle.openpgp.PGPUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

public class PgpUtilApi {

    public KeyDescription getKeyDescription(String text) throws IOException, PGPException, PgpError {
        try {
            InputStream inputStream = (new ByteArrayInputStream(text.getBytes()));
            boolean isPrivate;
            PGPPublicKey key;
            try {
                key = KeyRingReader.readPublicKeyRing(PGPUtil.getDecoderStream(inputStream)).getPublicKey();
                isPrivate = false;

            } catch (Throwable e) {
                inputStream.reset();
                key = KeyRingReader.readSecretKeyRing(PGPUtil.getDecoderStream(inputStream)).getPublicKey();
                isPrivate = true;
            }
            ArrayList<String> users = new ArrayList<String>();
            Iterator<String> iterator = key.getUserIDs();
            while (iterator.hasNext())
                users.add(iterator.next());


            return new KeyDescription(isPrivate, users, key.getBitStrength());
        } catch (Throwable e) {
            if (e instanceof PgpError) {
                throw (PgpError) e;
            } else {
                throw new PgpError(PgpErrorCase.Undefined);
            }
        }
    }

    public String[] createKeys(int length, String email, String password) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        RsaLength rsaLength = RsaLength._8192;

        if (length <= 1024)
            rsaLength = RsaLength._1024;
        else if (length <= 2048)
            rsaLength = RsaLength._2048;
        else if (length <= 3072)
            rsaLength = RsaLength._3072;
        else if (length <= 4096)
            rsaLength = RsaLength._4096;


        PGPKeyRing keyRing = new KeyRingBuilder().withMasterKey(
                KeySpec.getBuilder(RSA_GENERAL.withLength(rsaLength))
                        .withDefaultKeyFlags()
                        .withDefaultAlgorithms())
                .withPrimaryUserId(email)
                .withPassphrase(new Passphrase(password.toCharArray()))
                .build();

        ByteArrayOutputStream secretOut = new ByteArrayOutputStream();
        ByteArrayOutputStream publicOut = new ByteArrayOutputStream();
        ArmoredOutputStream armoredSecretOut = new ArmoredOutputStream(secretOut);
        ArmoredOutputStream armoredPublicOut = new ArmoredOutputStream(publicOut);
        armoredSecretOut.write(keyRing.getSecretKeys().getEncoded());
        armoredPublicOut.write(keyRing.getPublicKeys().getEncoded());
        armoredSecretOut.close();
        armoredPublicOut.close();

        return new String[]{new String(publicOut.toByteArray()), new String(secretOut.toByteArray())};
    }


    public boolean checkKeyPassword(String privateKey, final String password) {
        try {
            PGPPrivateKey key = getPrivateKey(privateKey, password);
            return key != null;
        } catch (Throwable e) {
            return false;
        }
    }

    static PGPPrivateKey getPrivateKey(String privateKey, final String password) throws PgpError {
        try {

            KeyRingProtectionSettings setting = new KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.MD5, 0);
            PGPSecretKeyRing secretKeys = new KeyRingReader().secretKeyRing(privateKey);
            PasswordBasedSecretKeyRingProtector secretKeyRingProtector = new PasswordBasedSecretKeyRingProtector(setting, new SecretKeyPassphraseProvider() {
                @Override
                public Passphrase getPassphraseFor(Long keyId) {
                    return new Passphrase(password.toCharArray());
                }
            });
            for (PGPSecretKey key : secretKeys) {
                try {
                    return key.extractPrivateKey(secretKeyRingProtector.getDecryptor(key.getKeyID()));
                } catch (Throwable e) {

                }
            }
        } catch (Throwable e) {

        }
        throw new PgpError(PgpErrorCase.InvalidPassword);
    }

    static PGPPublicKeyRingCollection getPublicKeyRing(String[] publicKeys) throws PgpError {
        try {
            PGPPublicKeyRing[] publicKeyRings = new PGPPublicKeyRing[publicKeys.length];
            int i = 0;
            for (String publicKey : publicKeys) {
                publicKeyRings[i] = KeyRingReader.readPublicKeyRing(new ByteArrayInputStream(publicKey.getBytes()));
                i++;
            }
            return new PGPPublicKeyRingCollection(Arrays.asList(publicKeyRings));
        } catch (Throwable e) {
            throw new PgpError(PgpErrorCase.InvalidMessage);
        }
    }
}
