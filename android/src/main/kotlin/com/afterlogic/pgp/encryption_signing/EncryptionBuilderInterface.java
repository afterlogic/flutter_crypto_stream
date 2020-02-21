
package com.afterlogic.pgp.encryption_signing;


import com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import com.afterlogic.pgp.algorithm.HashAlgorithm;
import com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;
import com.afterlogic.pgp.exception.SecretKeyNotFoundException;
import com.afterlogic.pgp.key.protection.SecretKeyRingProtector;
import com.afterlogic.pgp.key.selection.keyring.PublicKeyRingSelectionStrategy;
import com.afterlogic.pgp.key.selection.keyring.SecretKeyRingSelectionStrategy;
import com.afterlogic.pgp.util.MultiMap;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

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
                                 HashAlgorithm hashAlgorithm,
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
