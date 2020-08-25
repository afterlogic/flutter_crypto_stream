package lib.com.afterlogic.pgp;

import java.util.ArrayList;

public class KeyDescription {
    private final boolean isPrivate;
    private final ArrayList<String> emails;
    private final int length;
    private final String armoredKey;

    public int getLength() {
        return length;
    }

    public ArrayList<String> getEmails() {
        return emails;
    }

    public boolean isPrivate() {
        return isPrivate;
    }

    public KeyDescription(boolean isPrivate, ArrayList<String> emails, int length, String armoredKey) {
        this.isPrivate = isPrivate;
        this.emails = emails;
        this.length = length;
        this.armoredKey = armoredKey;
    }

    public String getArmoredKey() {
        return armoredKey;
    }
}
