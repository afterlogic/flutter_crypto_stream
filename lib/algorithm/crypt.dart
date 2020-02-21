import 'package:flutter/services.dart';

import '../error/crypto_exception.dart';
import '../error/pgp_error.dart';

const _event = EventChannel("crypto_event");
const _method = MethodChannel("crypto_method");

abstract class Crypt {
  String get algorithm;

  Future<dynamic> method(String method, List arg) async {
    try {
      return await _method.invokeMethod(
        algorithm + "." + method,
        arg,
      );
    } catch (e, stack) {
      if (e is PlatformException) {
        switch (e.code) {
          case "0":
            throw PgpSignError(e.code, e, stack);
          case "1":
            throw PgpInputError(e.code, e, stack);
          default:
            throw CryptoException("", e, stack);
        }
      }
      throw CryptoException("", e, stack);
    }
  }

  Stream<dynamic> event(String method, List arg) {
    return _event
        .receiveBroadcastStream(arg..insert(0, algorithm + "." + method));
  }
}
