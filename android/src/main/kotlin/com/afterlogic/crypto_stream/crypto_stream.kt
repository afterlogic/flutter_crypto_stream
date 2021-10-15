package com.afterlogic.crypto_stream

import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.reactivex.Completable
import io.reactivex.Scheduler
import io.reactivex.Single
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.internal.schedulers.SingleScheduler
import io.reactivex.subjects.BehaviorSubject
import lib.com.afterlogic.pgp.AesApi.performCryption
import lib.com.afterlogic.pgp.PgpApi
import lib.com.afterlogic.pgp.PgpError
import lib.com.afterlogic.pgp.PgpUtilApi
import lib.com.afterlogic.pgp.platform_stream.PlatformInputStream
import lib.com.afterlogic.pgp.platform_stream.PlatformOutputStream
import lib.com.afterlogic.pgp.platform_stream.StreamCallback
import lib.com.afterlogic.pgp.platform_stream.StreamSink
import lib.org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.security.Security

class crypto_stream : FlutterPlugin, MethodCallHandler, EventChannel.StreamHandler {

    private val executionScheduler: Scheduler = SingleScheduler()
    private val disposable = CompositeDisposable()
    private val subject = BehaviorSubject.create<() -> Unit>()
    private val pgpApi = PgpApi()
    private val pgpUtilApi = PgpUtilApi()
    private var output: PlatformOutputStream? = null
    private var input: PlatformInputStream? = null
    private var flutterCallback = FlutterCallback()

    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel

    init {
        Security.addProvider(BouncyCastleProvider())
        subject
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe {
                it()
            }.let {
                disposable.add(it)
            }
    }

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel = MethodChannel(flutterPluginBinding.binaryMessenger, "crypto_method")
        methodChannel.setMethodCallHandler(this)
        eventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "crypto_event")
        eventChannel.setStreamHandler(this)
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        val arguments = call.arguments as List<*>
        val route = call.method.split(".")
        val algorithm = route.first()
        val method = route.last()

        println("$algorithm.$method")
        if (algorithm == "pgp" && method == "closeStream") {
            flutterCallback.close()
            flutterCallback.result = result
            return
        }
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
                            pgpApi.encrypt(
                                privateKey,
                                publicKeys?.toTypedArray(),
                                password,
                                input,
                                output
                            )
                        }
                    }
                    "decrypt" -> {
                        val privateKey = arg.next() as String?
                        val publicKeys = arg.next() as List<String>?
                        val password = arg.next() as String?

                        streamExecutor(events) {
                            pgpApi.decrypt(
                                privateKey,
                                publicKeys?.toTypedArray(),
                                password,
                                input,
                                output
                            )
                        }
                    }

                    "symmetricallyEncrypt" -> {
                        val tempFile = arg.next() as String
                        val password = arg.next() as String
                        val length = (arg.next() as Number).toLong()

                        streamExecutor(events) {
                            pgpApi.symmetricallyEncrypt(
                                input,
                                output,
                                File(tempFile),
                                length,
                                password
                            )
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
            try {
                create()
                it.onComplete()
            } catch (e: Throwable) {
                it.onError(e)
            }
            subject.onNext {
                stop()
            }
        }
            .subscribeOn(executionScheduler)
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe({
                subject.onNext { events.endOfStream() }

            }, {
                it.printStackTrace()
                when (it) {
                    is PgpError -> events.error(it.errorCase.name, "", "")
                    else -> events.error(it.javaClass.toString(), it.message, "")
                }


            })
            .let {
                disposable.add(it)
            }
    }

    override fun onCancel(arguments: Any?) {}

    private fun stop() {
        output?.close()
        input?.close()
        output = null
        input = null
        flutterCallback = FlutterCallback()
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

                return performCryption(fileData, rawKey, iv, isLast, isDecrypt)
            }
            "pgp" -> {
                when (method) {
                    "getKeyDescription" -> {
                        val key = arg.next() as String

                        val result = pgpUtilApi.getKeyDescription(key)

                        return arrayListOf(
                            result.length,
                            result.emails,
                            result.isPrivate,
                            result.armoredKey
                        )
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


    inner class FlutterCallback : StreamCallback() {
        var inputStream: PlatformInputStream? = null
        var result: Result? = null

        fun data(byteArray: ByteArray) {
            inputStream?.addBuffer(byteArray)
        }

        override fun close() {
            inputStream?.onClose()
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

