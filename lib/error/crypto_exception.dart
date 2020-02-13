class CryptoException {
  final String message;

  CryptoException(this.message, e, stack) {
    print("encrypt err: $e");
    print("encrypt stack: $stack");
  }
}
