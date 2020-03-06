
package lib.com.afterlogic.pgp.algorithm;

import lib.org.bouncycastle.bcpg.sig.KeyFlags;

import java.util.ArrayList;
import java.util.List;

public enum KeyFlag {

    CERTIFY_OTHER  (KeyFlags.CERTIFY_OTHER),
    SIGN_DATA      (KeyFlags.SIGN_DATA),
    ENCRYPT_COMMS  (KeyFlags.ENCRYPT_COMMS),
    ENCRYPT_STORAGE(KeyFlags.ENCRYPT_STORAGE),
    SPLIT          (KeyFlags.SPLIT),
    AUTHENTICATION (KeyFlags.AUTHENTICATION),
    SHARED         (KeyFlags.SHARED),
    ;

    private final int flag;

    KeyFlag(int flag) {
        this.flag = flag;
    }

    public int getFlag() {
        return flag;
    }

    public static List<KeyFlag> fromInteger(int bitmask) {
        List<KeyFlag> flags = new ArrayList<>();
        for (KeyFlag f : KeyFlag.values()) {
            if ((bitmask & f.flag) != 0) {
                flags.add(f);
            }
        }
        return flags;
    }
}
