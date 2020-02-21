import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'crypt.dart';

class Pgp extends Crypt {
  @override
  final algorithm = "pgp";

  Future _sendData(List<int> data) {
    return method("sendData", [Uint8List.fromList(data)]);
  }

  PlatformSink platformSink() {
    return PlatformSink((data) {
      return _sendData(data);
    }, () {
      return _sendData([-1]);
    });
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
    ).map((item) {
      return item as List<int>;
    });
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
    ).map((item) {
      return item as List<int>;
    });
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
    ).map((item) {
      return item as List<int>;
    });
  }

  Stream<List<int>> symmetricallyDecrypt(
    String password,
  ) {
    return event(
      "symmetricallyDecrypt",
      [
        password,
      ],
    ).map((item) {
      return item as List<int>;
    });
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

    return KeyDescription(list[0], List.from(list[1]), list[2]);
  }
}

class PlatformSink extends Sink<List<int>> {
  final Future Function(List<int>) _onAdd;
  final Future Function() _onClose;

  PlatformSink(this._onAdd, this._onClose);

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

  KeyDescription(this.length, this.emails, this.isPrivate);
}

class KeyPair {
  final String publicKey;
  final String privateKey;

  KeyPair(this.publicKey, this.privateKey);
}
