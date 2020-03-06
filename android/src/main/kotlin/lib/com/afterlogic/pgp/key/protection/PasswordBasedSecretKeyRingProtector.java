
package lib.com.afterlogic.pgp.key.protection;




import lib.com.afterlogic.pgp.util.Passphrase;

import lib.org.bouncycastle.openpgp.PGPException;
import lib.org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import lib.org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import lib.org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import lib.org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import lib.org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import lib.org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;


public class PasswordBasedSecretKeyRingProtector implements SecretKeyRingProtector {

    private static final PGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();

    protected final KeyRingProtectionSettings protectionSettings;
    protected final SecretKeyPassphraseProvider passphraseProvider;


    public PasswordBasedSecretKeyRingProtector(KeyRingProtectionSettings settings, SecretKeyPassphraseProvider passphraseProvider) {
        this.protectionSettings = settings;
        this.passphraseProvider = passphraseProvider;
    }

    @Override

    public PBESecretKeyDecryptor getDecryptor(Long keyId) {
        Passphrase passphrase = passphraseProvider.getPassphraseFor(keyId);
        return new BcPBESecretKeyDecryptorBuilder(calculatorProvider)
                .build(passphrase != null ? passphrase.getChars() : null);
    }

    @Override

    public PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException {
        Passphrase passphrase = passphraseProvider.getPassphraseFor(keyId);
        return new BcPBESecretKeyEncryptorBuilder(
                protectionSettings.getEncryptionAlgorithm().getAlgorithmId(),
                calculatorProvider.get(protectionSettings.getHashAlgorithm().getAlgorithmId()),
                protectionSettings.getS2kCount())
                .build(passphrase != null ? passphrase.getChars() : null);
    }
}
