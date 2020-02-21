import 'package:crypto_plugin/error/crypto_exception.dart';

class PgpSignError extends CryptoException {
  PgpSignError(String message, e, stack) : super(message, e, stack);
}

class PgpInputError extends CryptoException {
  PgpInputError(String message, e, stack) : super(message, e, stack);
}
