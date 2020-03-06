
package lib.com.afterlogic.pgp.key.generation;


import lib.com.afterlogic.pgp.algorithm.HashAlgorithmUtil;
import lib.com.afterlogic.pgp.algorithm.KeyFlag;
import lib.com.afterlogic.pgp.key.collection.PGPKeyRingUtil;
import lib.com.afterlogic.pgp.key.generation.type.ECDH;
import lib.com.afterlogic.pgp.key.generation.type.ECDSA;
import lib.com.afterlogic.pgp.key.generation.type.KeyType;
import lib.com.afterlogic.pgp.key.generation.type.RSA_GENERAL;
import lib.com.afterlogic.pgp.key.generation.type.curve.EllipticCurve;
import lib.com.afterlogic.pgp.key.generation.type.length.RsaLength;
import lib.com.afterlogic.pgp.util.Passphrase;

import lib.org.bouncycastle.bcpg.sig.KeyFlags;
import lib.org.bouncycastle.openpgp.PGPEncryptedData;
import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPKeyPair;
import lib.org.bouncycastle.openpgp.PGPKeyRingGenerator;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;
import lib.org.bouncycastle.openpgp.PGPSignature;
import lib.org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import lib.org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import lib.org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import lib.org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import lib.org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import lib.org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import lib.org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import lib.org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

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


    public PGPKeyRingUtil simpleRsaKeyRing(String userId, RsaLength length)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return withMasterKey(
                KeySpec.getBuilder(RSA_GENERAL.withLength(length))
                        .withDefaultKeyFlags()
                        .withDefaultAlgorithms())
                .withPrimaryUserId(userId)
                .withoutPassphrase()
                .build();
    }


    public PGPKeyRingUtil simpleEcKeyRing(String userId)
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
            public PGPKeyRingUtil build() throws NoSuchAlgorithmException, PGPException,
                    InvalidAlgorithmParameterException {

                                PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
                        .build()
                        .get(HashAlgorithmUtil.SHA1.getAlgorithmId());

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
                        certKey.getPublicKey().getAlgorithm(), HashAlgorithmUtil.SHA512.getAlgorithmId());

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

                return new PGPKeyRingUtil(publicKeys, secretKeys);
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
