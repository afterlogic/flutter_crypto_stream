package com.afterlogic.crypto_stream

import com.afterlogic.crypto_stream.aes.Aes
import lib.com.afterlogic.pgp.PgpApi
import lib.com.afterlogic.pgp.PgpError
import lib.com.afterlogic.pgp.PgpUtilApi
import lib.com.afterlogic.pgp.platform_stream.PlatformInputStream
import lib.com.afterlogic.pgp.platform_stream.PlatformOutputStream
import lib.com.afterlogic.pgp.platform_stream.StreamCallback
import lib.com.afterlogic.pgp.platform_stream.StreamSink
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar
import io.reactivex.Completable
import io.reactivex.Scheduler
import io.reactivex.Single
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.internal.schedulers.SingleScheduler
import io.reactivex.subjects.BehaviorSubject
import java.io.File

class crypto_stream : MethodCallHandler, EventChannel.StreamHandler {

    private val executionScheduler: Scheduler = SingleScheduler()
    private val disposable = CompositeDisposable()
    private val subject = BehaviorSubject.create<() -> Unit>()
    private val pgpApi = PgpApi()
    private val pgpUtilApi = PgpUtilApi()
    private var output: PlatformOutputStream? = null
    private var input: PlatformInputStream? = null
    private var flutterCallback = FlutterCallback()


    init {
        subject
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe {
                    it()
                }.let {
                    disposable.add(it)
                }
    }

    @Suppress("UNCHECKED_CAST")
    override fun onListen(arguments: Any, events: EventChannel.EventSink) {


        val arg = (arguments as List<*>).iterator()

        val route = (arg.next() as String).split(".")
        val algorithm = route.first()
        val method = route.last()

        output = PlatformOutputStream(FlutterSink(events))
        input = PlatformInputStream(flutterCallback)
        flutterCallback.inputStream = input
        when (algorithm) {
            "pgp" -> {
                when (method) {
                    "encrypt" -> {
                        val privateKey = arg.next() as String?
                        val publicKeys = arg.next() as List<String>?
                        val password = arg.next() as String?
                        streamExecutor(events) {
                            pgpApi.encrypt(privateKey, publicKeys?.toTypedArray(), password, input, output)
                        }
                    }
                    "decrypt" -> {
                        val privateKey = arg.next() as String?
                        val publicKeys = arg.next() as List<String>?
                        val password = arg.next() as String?

                        streamExecutor(events) {
                            pgpApi.decrypt(privateKey, publicKeys?.toTypedArray(), password, input, output)
                        }
                    }

                    "symmetricallyEncrypt" -> {
                        val tempFile = arg.next() as String
                        val password = arg.next() as String
                        val length = (arg.next() as Number).toLong()

                        streamExecutor(events) {
                            pgpApi.symmetricallyEncrypt(input, output, File(tempFile), length, password)
                        }
                    }

                    "symmetricallyDecrypt" -> {

                        val password = arg.next() as String

                        streamExecutor(events) {
                            pgpApi.symmetricallyDecrypt(input, output, password)
                        }
                    }

                }
            }
        }
    }

    private fun streamExecutor(events: EventChannel.EventSink, create: () -> Unit) {
        Completable.create {
            create()
            it.onComplete()
        }
                .subscribeOn(executionScheduler)
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe({
                    events.endOfStream()
                }, {
                    it.printStackTrace()
                    when (it) {
                        is PgpError -> events.error(it.errorCase.name, "", "")
                        else -> events.error(it.javaClass.toString(), it.message, "")
                    }

                    events.endOfStream()
                })
                .let {
                    disposable.add(it)
                }
    }

    override fun onCancel(arguments: Any?) {
        output?.close()
        input?.close()
    }


    override fun onMethodCall(call: MethodCall, result: Result) {

        val arguments = call.arguments as List<*>
        val route = call.method.split(".")
        val algorithm = route.first()
        val method = route.last()

        println("$algorithm.$method")

        if (algorithm == "pgp" && method == "sendData") {
            flutterCallback.data(arguments[0] as ByteArray)
            flutterCallback.result = result
            return
        }

        Single.create<Any> {
            try {
                it.onSuccess(methodExecute(algorithm, method, arguments))
            } catch (e: Throwable) {
                it.onError(e)
            }
        }
                .subscribeOn(executionScheduler)
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe({
                    result.success(it)
                }, {
                    it.printStackTrace()
                    when (it) {
                        is NotImplemented -> result.notImplemented()
                        is PgpError -> result.error(it.errorCase.name, "", "")
                        else -> result.error(it.javaClass.toString(), it.message, "")
                    }
                }).let {
                    disposable.add(it)
                }

    }

    @Suppress("UNCHECKED_CAST")
    private fun methodExecute(algorithm: String, method: String, arguments: List<*>): Any {
        val arg = arguments.iterator()
        when (algorithm) {
            "aes" -> {
                val fileData = arg.next() as ByteArray
                val rawKey = arg.next() as String
                val iv = arg.next() as String
                val isLast = arg.next() as Boolean
                val isDecrypt = method == "decrypt"

                return Aes.performCryption(fileData, rawKey, iv, isLast, isDecrypt)
            }
            "pgp" -> {
                when (method) {
                    "getKeyDescription" -> {
                        val key = arg.next() as String

                        val result = pgpUtilApi.getKeyDescription(key)

                        return arrayListOf(result.length, result.emails, result.isPrivate)
                    }
                    "createKeys" -> {
                        val length = (arg.next() as Number).toInt()
                        val email = arg.next() as String
                        val password = arg.next() as String

                        val result = pgpUtilApi.createKeys(length, email, password)
                        return listOf(result[0], result[1])
                    }
                    "checkKeyPassword" -> {
                        val key = arg.next() as String
                        val password = arg.next() as String

                        return pgpUtilApi.checkKeyPassword(key, password)
                    }
                    "lastVerifyResult" -> {
                        return pgpApi.lastVerifyResult
                    }
                    "sign" -> {
                        val text = arg.next() as String
                        val privateKey = arg.next() as String
                        val password = arg.next() as String
                        return pgpApi.sign(text, privateKey, password)
                    }
                    "verify" -> {
                        val text = arg.next() as String
                        val publicKey = arg.next() as String

                        return pgpApi.verify(text, arrayOf(publicKey))
                    }
                }
            }
        }
        throw  NotImplemented()
    }

    private class NotImplemented : Throwable()

    companion object {
        @JvmStatic
        fun registerWith(registrar: Registrar) {
            val channel = MethodChannel(registrar.messenger(), "crypto_method")
            val event = EventChannel(registrar.messenger(), "crypto_event")
            val plugin = crypto_stream()
            event.setStreamHandler(plugin)
            channel.setMethodCallHandler(plugin)

        }
    }

    inner class FlutterCallback : StreamCallback() {
        var inputStream: PlatformInputStream? = null
        var result: Result? = null

        fun data(byteArray: ByteArray) {
            inputStream?.addBuffer(byteArray)
        }

        override fun invoke() {
            subject.onNext {
                result?.success(null)
                result = null
            }
        }
    }

    inner class FlutterSink(private val events: EventChannel.EventSink) : StreamSink() {

        override fun add(bytes: ByteArray) {
            subject.onNext {
                events.success(bytes)
            }
        }
    }

}

