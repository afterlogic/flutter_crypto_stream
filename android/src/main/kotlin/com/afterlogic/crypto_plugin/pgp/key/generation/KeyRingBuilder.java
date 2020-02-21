
package com.afterlogic.crypto_plugin.pgp.key.generation;


import com.afterlogic.crypto_plugin.pgp.algorithm.HashAlgorithm;
import com.afterlogic.crypto_plugin.pgp.algorithm.KeyFlag;
import com.afterlogic.crypto_plugin.pgp.key.collection.PGPKeyRing;
import com.afterlogic.crypto_plugin.pgp.key.generation.type.ECDH;
import com.afterlogic.crypto_plugin.pgp.key.generation.type.ECDSA;
import com.afterlogic.crypto_plugin.pgp.key.generation.type.KeyType;
import com.afterlogic.crypto_plugin.pgp.key.generation.type.RSA_GENERAL;
import com.afterlogic.crypto_plugin.pgp.key.generation.type.curve.EllipticCurve;
import com.afterlogic.crypto_plugin.pgp.key.generation.type.length.RsaLength;
import com.afterlogic.crypto_plugin.pgp.util.Passphrase;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class KeyRingBuilder implements KeyRingBuilderInterface {

    private final Charset UTF8 = Charset.forName("UTF-8");

    private List<KeySpec> keySpecs = new ArrayList<>();
    private String userId;
    private Passphrase passphrase;


    public PGPKeyRing simpleRsaKeyRing(String userId, RsaLength length)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return withMasterKey(
                KeySpec.getBuilder(RSA_GENERAL.withLength(length))
                        .withDefaultKeyFlags()
                        .withDefaultAlgorithms())
                .withPrimaryUserId(userId)
                .withoutPassphrase()
                .build();
    }


    public PGPKeyRing simpleEcKeyRing(String userId)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return withSubKey(
                KeySpec.getBuilder(ECDH.fromCurve(EllipticCurve._P256))
                        .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
                        .withDefaultAlgorithms())
                .withMasterKey(
                        KeySpec.getBuilder(ECDSA.fromCurve(EllipticCurve._P256))
                                .withKeyFlags(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId)
                .withoutPassphrase()
                .build();
    }

    @Override
    public KeyRingBuilderInterface withSubKey(KeySpec type) {
        KeyRingBuilder.this.keySpecs.add(type);
        return this;
    }

    @Override
    public WithPrimaryUserId withMasterKey(KeySpec spec) {
        if ((spec.getSubpackets().getKeyFlags() & KeyFlags.CERTIFY_OTHER) == 0) {
            throw new IllegalArgumentException("Certification Key MUST have KeyFlag CERTIFY_OTHER");
        }
        KeyRingBuilder.this.keySpecs.add(0, spec);
        return new WithPrimaryUserIdImpl();
    }

    class WithPrimaryUserIdImpl implements WithPrimaryUserId {

        @Override
        public WithPassphrase withPrimaryUserId(String userId) {
            KeyRingBuilder.this.userId = userId;
            return new WithPassphraseImpl();
        }

        @Override
        public WithPassphrase withPrimaryUserId(byte[] userId) {
            return withPrimaryUserId(new String(userId, UTF8));
        }
    }

    class WithPassphraseImpl implements WithPassphrase {

        @Override
        public Build withPassphrase(Passphrase passphrase) {
            KeyRingBuilder.this.passphrase = passphrase;
            return new BuildImpl();
        }

        @Override
        public Build withoutPassphrase() {
            KeyRingBuilder.this.passphrase = null;
            return new BuildImpl();
        }

        class BuildImpl implements Build {

            @Override
            public PGPKeyRing build() throws NoSuchAlgorithmException, PGPException,
                    InvalidAlgorithmParameterException {

                                PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
                        .build()
                        .get(HashAlgorithm.SHA1.getAlgorithmId());

                                PBESecretKeyEncryptor encryptor = passphrase == null ?
                        null : // unencrypted key pair, otherwise AES-256 encrypted
                        new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calculator)
                                .build(passphrase != null ? passphrase.getChars() : null);

                if (passphrase != null) {
                    passphrase.clear();
                }

                                KeySpec certKeySpec = keySpecs.get(0);
                                keySpecs.remove(0);

                                PGPKeyPair certKey = generateKeyPair(certKeySpec);

                                PGPContentSignerBuilder signer = new JcaPGPContentSignerBuilder(
                        certKey.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId());

                PGPSignatureSubpacketVector hashedSubPackets = certKeySpec.getSubpackets();

                                PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(
                        PGPSignature.POSITIVE_CERTIFICATION, certKey,
                        userId, calculator,
                        hashedSubPackets, null, signer, encryptor);

                for (KeySpec subKeySpec : keySpecs) {
                    PGPKeyPair subKey = generateKeyPair(subKeySpec);
                    if (subKeySpec.isInheritedSubPackets()) {
                        ringGenerator.addSubKey(subKey);
                    } else {
                        ringGenerator.addSubKey(subKey, subKeySpec.getSubpackets(), null);
                    }
                }

                PGPPublicKeyRing publicKeys = ringGenerator.generatePublicKeyRing();
                PGPSecretKeyRing secretKeys = ringGenerator.generateSecretKeyRing();

                return new PGPKeyRing(publicKeys, secretKeys);
            }

            private PGPKeyPair generateKeyPair(KeySpec spec)
                    throws NoSuchAlgorithmException, PGPException,
                    InvalidAlgorithmParameterException {
                KeyType type = spec.getKeyType();
                KeyPairGenerator certKeyGenerator = KeyPairGenerator.getInstance(type.getName());
                certKeyGenerator.initialize(type.getAlgorithmSpec());

                                KeyPair keyPair = certKeyGenerator.generateKeyPair();

                                PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(type.getAlgorithm().getAlgorithmId(),
                        keyPair, new Date());

                return pgpKeyPair;
            }
        }
    }
}
