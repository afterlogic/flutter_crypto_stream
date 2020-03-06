
package lib.com.afterlogic.pgp.key.selection.key;



import lib.com.afterlogic.pgp.util.MultiMap;

import lib.org.bouncycastle.openpgp.PGPSecretKey;
import lib.org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


public abstract class SecretKeySelectionStrategy<O> implements KeySelectionStrategy<PGPSecretKey, PGPSecretKeyRing, O> {

    @Override
    public Set<PGPSecretKey> selectKeysFromKeyRing(O identifier,  PGPSecretKeyRing ring) {
        Set<PGPSecretKey> keys = new HashSet<>();
        for (Iterator<PGPSecretKey> i = ring.getSecretKeys(); i.hasNext(); ) {
            PGPSecretKey key = i.next();
            if (accept(identifier, key)) keys.add(key);
        }
        return keys;
    }

    @Override
    public MultiMap<O, PGPSecretKey> selectKeysFromKeyRings(MultiMap<O, PGPSecretKeyRing> keyRings) {
        MultiMap<O, PGPSecretKey> keys = new MultiMap<>();
        for (O identifier : keyRings.keySet()) {
            for (PGPSecretKeyRing ring : keyRings.get(identifier)) {
                keys.put(identifier, selectKeysFromKeyRing(identifier, ring));
            }
        }
        return keys;
    }
}
