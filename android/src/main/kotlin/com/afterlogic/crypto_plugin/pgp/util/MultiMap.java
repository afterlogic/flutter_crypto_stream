
package com.afterlogic.crypto_plugin.pgp.util;



import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class MultiMap<K, V> {

    private final Map<K, Set<V>> map;

    public MultiMap() {
        map = new HashMap<>();
    }

    public MultiMap( MultiMap<K, V> other) {
        this.map = new HashMap<>();
        for (K k : other.map.keySet()) {
            map.put(k, new HashSet<>(other.map.get(k)));
        }
    }

    public MultiMap( Map<K, Set<V>> content) {
        this.map = new HashMap<>(content);
    }

    public int size() {
        return map.size();
    }

    public boolean isEmpty() {
        return map.isEmpty();
    }

    public boolean containsKey(K o) {
        return map.containsKey(o);
    }

    public boolean containsValue(V o) {
        for (Set<V> values : map.values()) {
            if (values.contains(o)) return true;
        }
        return false;
    }

    public Set<V> get(K o) {
        return map.get(o);
    }

    public void put(K k, V v) {
        Set<V> values = map.get(k);
        if (values == null) {
            values = new HashSet<>();
            map.put(k, values);
        }
        values.add(v);
    }

    public void put(K k, Set<V> vs) {
        for (V v : vs) {
            put(k, v);
        }
    }

    public void removeAll(K o) {
        map.remove(o);
    }

    public void remove(K o, V v) {
        Set<V> vs = map.get(o);
        if (vs == null) return;
        vs.remove(v);
    }

    public void putAll(MultiMap<K, V> other) {
        for (K key : other.keySet()) {
            put(key, other.get(key));
        }
    }

    public void clear() {
        map.clear();
    }

    public Set<K> keySet() {
        return map.keySet();
    }

    public Collection<Set<V>> values() {
        return map.values();
    }

    public Set<Map.Entry<K, Set<V>>> entrySet() {
        return map.entrySet();
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }

        if (!(o instanceof MultiMap)) {
            return false;
        }

        if (this == o) {
            return true;
        }

        return map.equals(((MultiMap<?, ?>) o).map);
    }

    @Override
    public int hashCode() {
        return map.hashCode();
    }
}
