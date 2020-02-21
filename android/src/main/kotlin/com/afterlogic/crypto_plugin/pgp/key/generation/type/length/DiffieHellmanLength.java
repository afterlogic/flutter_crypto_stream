
package com.afterlogic.crypto_plugin.pgp.key.generation.type.length;

public enum DiffieHellmanLength implements KeyLength {

    _1024(1024),
    _2048(2048),
    _3072(3072),
    ;

    private final int length;

    DiffieHellmanLength(int length) {
        this.length = length;
    }

    @Override
    public int getLength() {
        return length;
    }

}
