package com.afterlogic.crypto_plugin.pgp

import com.afterlogic.crypto_plugin.crypto_stream.PlatformInputStream
import com.afterlogic.crypto_plugin.crypto_stream.PlatformOutputStream
import com.afterlogic.crypto_plugin.crypto_stream.StreamCallback
import com.afterlogic.crypto_plugin.crypto_stream.StreamSink
import org.junit.Test

class PlatformStreamTest {
    @Test
    fun platformStreamTest() {
        val array = arrayListOf<IntArray>()

        val output = PlatformOutputStream(object : StreamSink() {
            override fun add(bytes: IntArray, isEnd: Boolean) {

            }
        })
        val input = PlatformInputStream(object : StreamCallback() {
            override fun invoke() {

            }
        })
    }
}