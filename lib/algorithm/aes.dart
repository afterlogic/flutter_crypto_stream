import 'dart:typed_data';

import 'crypt.dart';

class Aes extends Crypt {
  Future<List<dynamic>> decrypt(
    List<int> fileBytes,
    String keyBase64,
    String ivBase64, [
    bool isLast = false,
  ]) async {
    if (fileBytes.length > chunkMaxSize) {
      throw Exception(
          "Passed chunk size for decryption (${fileBytes.length}) exceeds the max chunk size ($chunkMaxSize)");
    }
    final List result = await method(
      "decrypt",
      [Uint8List.fromList(fileBytes), keyBase64, ivBase64, isLast],
    );

    return new List<int>.from(result);
  }

  Future<List<int>> encrypt(
    List<int> fileBytes,
    String keyBase64,
    String ivBase64, [
    bool isLast = false,
  ]) async {
    if (fileBytes.length > chunkMaxSize) {
      throw Exception(
          "Passed chunk size for decryption (${fileBytes.length}) exceeds the max chunk size ($chunkMaxSize)");
    }
    final List<dynamic> decrypted = await method(
      "encrypt",
      [Uint8List.fromList(fileBytes), keyBase64, ivBase64, isLast],
    );

    return new List<int>.from(decrypted);
  }

  final algorithm = "aes";
  static int chunkMaxSize = 4000000;
}
