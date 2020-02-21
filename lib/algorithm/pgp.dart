import 'dart:async';
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

class CryptoProgress {}
