
package com.afterlogic.crypto_plugin.pgp.key.selection.key;



import com.afterlogic.crypto_plugin.pgp.util.MultiMap;

import java.util.Set;



public interface KeySelectionStrategy<K, R, O> {

    boolean accept(O identifier, K key);

    Set<K> selectKeysFromKeyRing(O identifier, R ring);

    MultiMap<O, K> selectKeysFromKeyRings(MultiMap<O, R> rings);

}
