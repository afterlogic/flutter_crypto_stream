
package lib.com.afterlogic.pgp.util;



import java.util.Arrays;

public class Passphrase {

    private final Object lock = new Object();

    private final char[] chars;
    private boolean valid = true;


    public Passphrase( char[] chars) {
        this.chars = chars;
    }


    public void clear() {
        synchronized (lock) {
            if (chars != null) {
                Arrays.fill(chars, ' ');
            }
            valid = false;
        }
    }


    @Override
    protected void finalize() throws Throwable {
        clear();
        super.finalize();
    }


    public  char[] getChars() {
        synchronized (lock) {
            if (!valid) {
                throw new IllegalStateException("Passphrase has been cleared.");
            }

            if (chars == null) {
                return null;
            }

            char[] copy = new char[chars.length];
            System.arraycopy(chars, 0, copy, 0, chars.length);
            return copy;
        }
    }


    public boolean isValid() {
        synchronized (lock) {
            return valid;
        }
    }


    public static Passphrase emptyPassphrase() {
        return new Passphrase(null);
    }
}
