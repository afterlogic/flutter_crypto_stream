package com.afterlogic.crypto_plugin.crypto_stream;


import java.io.IOException;
import java.io.OutputStream;

public class PlatformOutputStream extends OutputStream {
    private final StreamSink sink;
    private static final int BUFFER_SIZE = 16 << 8;
    private int[] buffer = new int[BUFFER_SIZE];
    private long count = 0;
    private int position = 0;

    public PlatformOutputStream(StreamSink sink) {
        this.sink = sink;
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
        sendBuffer();
        super.close();
    }

    private void sendBuffer() {
        count += BUFFER_SIZE;
        sink.add(buffer);
        position = 0;
        buffer = new int[BUFFER_SIZE];
    }


}

