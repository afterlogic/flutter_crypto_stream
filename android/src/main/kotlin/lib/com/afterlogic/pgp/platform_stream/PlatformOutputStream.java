package lib.com.afterlogic.pgp.platform_stream;


import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

public class PlatformOutputStream extends OutputStream {
    private final StreamSink sink;
    private static final int BUFFER_SIZE = 16 << 8;
    private byte[] buffer = new byte[BUFFER_SIZE];
    private boolean isClosed = false;
    private int position = 0;

    public PlatformOutputStream(StreamSink sink) {
        this.sink = sink;
    }


    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        sendBuffer();
        if (b.length == len && off == 0) {
            sink.add(b);
        } else {
            sink.add(Arrays.copyOfRange(b, off, len));
        }
    }


    @Override
    public void write(int b) {
        buffer[position] = (byte) b;
        position++;
        if (position == BUFFER_SIZE) {
            sendBuffer();
        }
    }


    @Override
    public void close() throws IOException {
        if(!isClosed) {
            isClosed = true;
            sendBuffer();
            super.close();
        }
    }

    private void sendBuffer() {
        if (position != 0) {
            sink.add(Arrays.copyOfRange(buffer, 0, position));
            position = 0;
            buffer = new byte[BUFFER_SIZE];
        }
    }


}

