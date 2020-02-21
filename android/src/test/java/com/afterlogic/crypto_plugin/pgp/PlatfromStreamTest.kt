package com.afterlogic.crypto_plugin.pgp

import com.afterlogic.pgp.platform_stream.PlatformInputStream
import com.afterlogic.pgp.platform_stream.PlatformOutputStream
import com.afterlogic.pgp.platform_stream.StreamCallback
import com.afterlogic.pgp.platform_stream.StreamSink
import org.junit.Test

class PlatformStreamTest {
    @Test
    fun platformStreamTest() {
        val array = arrayListOf<IntArray>()

        val output = PlatformOutputStream(object : StreamSink() {
            override fun add(bytes: ByteArray) {

            }
        })
        val input = PlatformInputStream(object : StreamCallback() {
            override fun invoke() {

            }
        })
    }
}