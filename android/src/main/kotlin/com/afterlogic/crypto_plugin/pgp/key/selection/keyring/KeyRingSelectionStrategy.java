
package com.afterlogic.crypto_plugin.pgp.key.selection.keyring;

import com.afterlogic.crypto_plugin.pgp.util.MultiMap;

import java.util.Set;

public interface KeyRingSelectionStrategy<R, C, O> {

    boolean accept(O identifier, R keyRing);

    Set<R> selectKeyRingsFromCollection(O identifier, C keyRingCollection);

    MultiMap<O, R> selectKeyRingsFromCollections(MultiMap<O, C> keyRingCollections);
}
