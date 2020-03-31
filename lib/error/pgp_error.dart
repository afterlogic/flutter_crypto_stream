import 'package:crypto_stream/error/crypto_exception.dart';

class PgpSignError extends CryptoException {
  PgpSignError(String message, e, stack) : super(message, e, stack);
}

class PgpInputError extends CryptoException {
  PgpInputError(String message, e, stack) : super(message, e, stack);
}
