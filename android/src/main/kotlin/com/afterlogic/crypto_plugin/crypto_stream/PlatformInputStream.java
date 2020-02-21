package com.afterlogic.crypto_plugin.crypto_stream;

import java.io.InputStream;
import java.util.concurrent.CountDownLatch;

public class PlatformInputStream extends InputStream {
    private boolean isClosed = false;
    private int bufferSize = 0;
    private byte[] buffer = new byte[0];
    private int position = 0;
    private final StreamCallback endBufferCallback;
    private CountDownLatch countDownLatch;

    public PlatformInputStream(StreamCallback endBufferCallback) {
        this.endBufferCallback = endBufferCallback;
    }

    public void addBuffer(byte[] buffer) {
        this.buffer = buffer;
        bufferSize = buffer.length;
        position = 0;
        if (buffer.length == 1 && buffer[0] == -1) {
            close();
        }
        if (countDownLatch != null) {
            countDownLatch.countDown();
        }
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
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        countDownLatch = null;
    }

    @Override
    public void close() {
        isClosed = true;
    }
}

