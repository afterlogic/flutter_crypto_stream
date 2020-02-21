
package com.afterlogic.pgp.key.selection.key.impl;



import com.afterlogic.pgp.key.selection.key.PublicKeySelectionStrategy;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.util.Arrays;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SignedByMasterKey {

    private static final Logger LOGGER = Logger.getLogger(SignedByMasterKey.class.getName());

    public static class PubkeySelectionStrategy extends PublicKeySelectionStrategy<PGPPublicKey> {

        @Override
        public boolean accept(PGPPublicKey masterKey,  PGPPublicKey key) {
                        if (Arrays.equals(masterKey.getFingerprint(), key.getFingerprint())) {
                return true;
            }

            Iterator<PGPSignature> signatures = key.getSignaturesForKeyID(masterKey.getKeyID());
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (signature.getSignatureType() == PGPSignature.SUBKEY_BINDING) {
                    try {
                        signature.init(new BcPGPContentVerifierBuilderProvider(), masterKey);
                        return signature.verifyCertification(masterKey, key);
                    } catch (PGPException e) {
                        LOGGER.log(Level.WARNING, "Could not verify subkey signature of key " +
                                Long.toHexString(masterKey.getKeyID()) + " on key " + Long.toHexString(key.getKeyID()));

                        return false;
                    }
                }
            }
            return false;
        }
    }
}
