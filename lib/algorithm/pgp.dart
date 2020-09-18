import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'crypt.dart';

class Pgp extends Crypt {
  @override
  final algorithm = "pgp";
  final Utf8Codec utf8 = Utf8Codec(allowMalformed: true);

  Future _sendData(List<int> data) {
    return method("sendData", [Uint8List.fromList(data)]);
  }

  Future _closeStream() {
    return method("closeStream", []);
  }

  _PlatformSink platformSink() {
    return _PlatformSink((data) {
      return _sendData(data);
    }, () {
      return _closeStream();
    });
  }

  Future<String> bufferPlatformSink(
    String text,
    Stream<List<int>> stream,
  ) async {
    final sink = platformSink();
    final future = utf8.decodeStream(stream);
    try {
      await sink.add(utf8.encode(text));
      sink.close();

      return await future;
    } catch (_) {
      sink.close();
      rethrow;
    }
  }

  Stream<List<int>> encrypt(
    String privateKey,
    List<String> publicKeys,
    String password,
  ) {
    return event(
      "encrypt",
      [
        privateKey,
        publicKeys,
        password,
      ],
    ).map(_byteStream);
  }

  Stream<List<int>> decrypt(
    String privateKey,
    List<String> publicKeys,
    String password,
  ) {
    return event(
      "decrypt",
      [
        privateKey,
        publicKeys,
        password,
      ],
    ).map(_byteStream);
  }

  Stream<List<int>> symmetricallyEncrypt(
    File tempFile,
    String password,
    int length,
  ) {
    return event(
      "symmetricallyEncrypt",
      [
        tempFile.path,
        password,
        length,
      ],
    ).map(_byteStream);
  }

  Stream<List<int>> symmetricallyDecrypt(
    String password,
  ) {
    return event(
      "symmetricallyDecrypt",
      [
        password,
      ],
    ).map(_byteStream);
  }

  Future<String> sign(
    String text,
    String privateKey,
    String password,
  ) async {
    final result = await method(
      "sign",
      [
        text,
        privateKey,
        password,
      ],
    );
    return result as String;
  }

  Future<String> verify(
    String text,
    String publicKey,
  ) async {
    final result = await method(
      "verify",
      [
        text,
        publicKey,
      ],
    );
    return result as String;
  }

  Future<bool> lastVerifyResult() async {
    final result = await method(
      "lastVerifyResult",
      [],
    );
    return result as bool;
  }

  Future<KeyPair> createKeys(
    int length,
    String email,
    String password,
  ) async {
    final result = await method(
      "createKeys",
      [length, email, password],
    );
    final list = result as List;

    return KeyPair(list[0], list[1]);
  }

  Future<bool> checkKeyPassword(String key, String password) async {
    final result = await method(
      "checkKeyPassword",
      [key, password],
    );
    return result as bool;
  }

  Future<KeyDescription> getKeyDescription(String key) async {
    final result = await method(
      "getKeyDescription",
      [key],
    );
    final list = result as List;

    return KeyDescription(list[0], List.from(list[1]), list[2], list[3]);
  }

  List<int> _byteStream(dynamic data) {
    return data as List<int>;
  }
}

class _PlatformSink extends Sink<List<int>> {
  final Future Function(List<int>) _onAdd;
  final Future Function() _onClose;

  _PlatformSink(this._onAdd, this._onClose);

  Future add(List<int> data) {
    return _onAdd(data);
  }

  Future close() {
    return _onClose();
  }
}

class KeyDescription {
  final int length;
  final List<String> emails;
  final bool isPrivate;
  final String armoredKey;

  KeyDescription(this.length, this.emails, this.isPrivate, this.armoredKey);
}

class KeyPair {
  final String publicKey;
  final String privateKey;

  KeyPair(this.publicKey, this.privateKey);
}
