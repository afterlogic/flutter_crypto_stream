
package lib.com.afterlogic.pgp.key.selection.keyring;



import lib.com.afterlogic.pgp.util.MultiMap;

import lib.org.bouncycastle.openpgp.PGPPublicKeyRing;
import lib.org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public abstract class PublicKeyRingSelectionStrategy<O> implements KeyRingSelectionStrategy<PGPPublicKeyRing, PGPPublicKeyRingCollection, O> {

    @Override
    public Set<PGPPublicKeyRing> selectKeyRingsFromCollection( O identifier,  PGPPublicKeyRingCollection keyRingCollection) {
        Set<PGPPublicKeyRing> accepted = new HashSet<>();
        for (Iterator<PGPPublicKeyRing> i = keyRingCollection.getKeyRings(); i.hasNext(); ) {
            PGPPublicKeyRing ring = i.next();
            if (accept(identifier, ring)) accepted.add(ring);
        }
        return accepted;
    }

    @Override
    public MultiMap<O, PGPPublicKeyRing> selectKeyRingsFromCollections(MultiMap<O, PGPPublicKeyRingCollection> keyRingCollections) {
        MultiMap<O, PGPPublicKeyRing> keyRings = new MultiMap<>();
        for (O identifier : keyRingCollections.keySet()) {
            for (PGPPublicKeyRingCollection collection : keyRingCollections.get(identifier)) {
                keyRings.put(identifier, selectKeyRingsFromCollection(identifier, collection));
            }
        }
        return keyRings;
    }
}
