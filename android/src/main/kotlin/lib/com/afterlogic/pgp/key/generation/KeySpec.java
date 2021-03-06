
package lib.com.afterlogic.pgp.key.generation;




import lib.com.afterlogic.pgp.key.generation.type.KeyType;

import lib.org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import lib.org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

public class KeySpec {

    private final KeyType keyType;
    private final PGPSignatureSubpacketGenerator subpacketGenerator;
    private final boolean inheritedSubPackets;

    KeySpec( KeyType type,
             PGPSignatureSubpacketGenerator subpacketGenerator,
            boolean inheritedSubPackets) {
        this.keyType = type;
        this.subpacketGenerator = subpacketGenerator;
        this.inheritedSubPackets = inheritedSubPackets;
    }


    KeyType getKeyType() {
        return keyType;
    }


    PGPSignatureSubpacketVector getSubpackets() {
        return subpacketGenerator != null ? subpacketGenerator.generate() : null;
    }

    boolean isInheritedSubPackets() {
        return inheritedSubPackets;
    }

    public static KeySpecBuilder getBuilder(KeyType type) {
        return new KeySpecBuilder(type);
    }
}
