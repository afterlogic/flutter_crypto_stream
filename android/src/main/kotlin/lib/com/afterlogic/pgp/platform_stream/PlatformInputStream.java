package lib.com.afterlogic.pgp.platform_stream;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class PlatformInputStream extends InputStream {
    private boolean isClosed = false;
    private byte[] buffer = new byte[0];
    private int position = 0;
    private final StreamCallback endBufferCallback;
    private CountDownLatch countDownLatch;

    public PlatformInputStream(StreamCallback endBufferCallback) {
        this.endBufferCallback = endBufferCallback;
    }

    public void addBuffer(byte[] buffer) {
        this.buffer = buffer;
        position = 0;
        if (buffer.length == 1 && buffer[0] == -1) {
            close();
        }
        if (countDownLatch != null) {
            countDownLatch.countDown();
        }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (off > 0) {
            readBuffer(null, off);
        }
        return readBuffer(b, len);
    }

    private int readBuffer(byte[] output, final int size) {
        int outPos = 0;
        while (outPos < size) {
            if (isClosed) {
                if (outPos == 0) {
                    return -1;
                }
                return outPos;
            }
            int len = Math.min(size - outPos, buffer.length - position);
            if (output != null) {
                System.arraycopy(buffer, position, output, outPos, len);
            }
            outPos += len;
            position += len;
            if (position >= buffer.length) {
                pause();
            }
        }
        return outPos;
    }

    @Override
    public int read() {
        if (isClosed) {
            return -1;
        }
        try {
            int current = buffer[position];
            position++;
            return current;
        } catch (Throwable e) {
            pause();
            return read();
        }
    }

    private void pause() {
        countDownLatch = new CountDownLatch(1);
        endBufferCallback.invoke();
        try {
            countDownLatch.await(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        countDownLatch = null;
    }

    @Override
    public void close() {
        if (countDownLatch != null) {
            countDownLatch.countDown();
        }
        if (!isClosed) {
            endBufferCallback.invoke();
            isClosed = true;
        }
    }
}

