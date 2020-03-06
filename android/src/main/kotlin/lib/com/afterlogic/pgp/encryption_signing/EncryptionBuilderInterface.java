
package lib.com.afterlogic.pgp.encryption_signing;


import lib.com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import lib.com.afterlogic.pgp.algorithm.HashAlgorithmUtil;
import lib.com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;
import lib.com.afterlogic.pgp.exception.SecretKeyNotFoundException;
import lib.com.afterlogic.pgp.key.protection.SecretKeyRingProtector;
import lib.com.afterlogic.pgp.key.selection.keyring.PublicKeyRingSelectionStrategy;
import lib.com.afterlogic.pgp.key.selection.keyring.SecretKeyRingSelectionStrategy;
import lib.com.afterlogic.pgp.util.MultiMap;

import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.PGPPublicKey;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import lib.org.bouncycastle.openpgp.PGPSecretKey;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import java.io.IOException;
import java.io.OutputStream;

public interface EncryptionBuilderInterface {

    ToRecipients onOutputStream(OutputStream outputStream);

    interface ToRecipients {

        WithAlgorithms toRecipients(PGPPublicKey... keys);

        WithAlgorithms toRecipients(PGPPublicKeyRing... keys);

        WithAlgorithms toRecipients(PGPPublicKeyRingCollection... keys);

        <O> WithAlgorithms toRecipients(PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                        MultiMap<O, PGPPublicKeyRingCollection> keys);

        SignWith doNotEncrypt();

    }

    interface WithAlgorithms {

        WithAlgorithms andToSelf(PGPPublicKey... keys);

        WithAlgorithms andToSelf(PGPPublicKeyRing... keys);

        WithAlgorithms andToSelf(PGPPublicKeyRingCollection keys);

        <O> WithAlgorithms andToSelf(PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                     MultiMap<O, PGPPublicKeyRingCollection> keys);

        SignWith usingAlgorithms(SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                 HashAlgorithmUtil hashAlgorithmUtil,
                                 CompressionAlgorithm compressionAlgorithm);

        SignWith usingSecureAlgorithms();

    }

    interface SignWith {

        <O> Armor signWith(SecretKeyRingProtector decryptor, PGPSecretKey... keys);

        <O> Armor signWith(SecretKeyRingProtector decryptor, PGPSecretKeyRing... keyRings);

        <O> Armor signWith(SecretKeyRingSelectionStrategy<O> selectionStrategy,
                           SecretKeyRingProtector decryptor,
                           MultiMap<O, PGPSecretKeyRingCollection> keys)
                throws SecretKeyNotFoundException;

        Armor doNotSign();

    }

    interface Armor {

        EncryptionStream asciiArmor() throws IOException, PGPException;

        EncryptionStream noArmor() throws IOException, PGPException;

    }

}
