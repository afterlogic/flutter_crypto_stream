
package lib.com.afterlogic.pgp.decryption_verification;



import java.io.IOException;
import java.io.InputStream;

public class DecryptionStream extends InputStream {

    private final InputStream inputStream;
    private final OpenPgpMetadata.Builder resultBuilder;
    private boolean isClosed = false;

    DecryptionStream( InputStream wrapped,  OpenPgpMetadata.Builder resultBuilder) {
        this.inputStream = wrapped;
        this.resultBuilder = resultBuilder;
    }

    @Override
    public int read() throws IOException {
        return inputStream.read();
    }

    @Override
    public void close() throws IOException {
        inputStream.close();
        this.isClosed = true;
    }

    public OpenPgpMetadata getResult() {
        if (!isClosed) {
            throw new IllegalStateException("DecryptionStream MUST be closed before the result can be accessed.");
        }
        return resultBuilder.build();
    }
}
