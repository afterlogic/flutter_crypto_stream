class CryptoException {
  final String message;
  final e;
  final stack;

  CryptoException(this.message, this.e, this.stack) {
    print("encrypt err: $e");
    print("encrypt stack: $stack");
  }
}
