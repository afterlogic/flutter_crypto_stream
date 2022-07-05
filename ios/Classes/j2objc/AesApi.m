//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/AesApi.java
//

#include "AesApi.h"
#include "Base64.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Boolean.h"
#include "javax/crypto/Cipher.h"
#include "javax/crypto/spec/IvParameterSpec.h"
#include "javax/crypto/spec/SecretKeySpec.h"

@implementation LibComAfterlogicPgpAesApi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpAesApi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSByteArray *)performCryptionWithByteArray:(IOSByteArray *)fileData
                                  withNSString:(NSString *)rawKey
                                  withNSString:(NSString *)iv
                           withJavaLangBoolean:(JavaLangBoolean *)isLast
                           withJavaLangBoolean:(JavaLangBoolean *)isDecrypt {
  return LibComAfterlogicPgpAesApi_performCryptionWithByteArray_withNSString_withNSString_withJavaLangBoolean_withJavaLangBoolean_(fileData, rawKey, iv, isLast, isDecrypt);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(performCryptionWithByteArray:withNSString:withNSString:withJavaLangBoolean:withJavaLangBoolean:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "performCryption", "[BLNSString;LNSString;LJavaLangBoolean;LJavaLangBoolean;", "LJavaxCryptoNoSuchPaddingException;LJavaSecurityNoSuchAlgorithmException;LJavaxCryptoBadPaddingException;LJavaxCryptoIllegalBlockSizeException;LJavaSecurityInvalidAlgorithmParameterException;LJavaSecurityInvalidKeyException;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpAesApi = { "AesApi", "lib.com.afterlogic.pgp", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpAesApi;
}

@end

void LibComAfterlogicPgpAesApi_init(LibComAfterlogicPgpAesApi *self) {
  NSObject_init(self);
}

LibComAfterlogicPgpAesApi *new_LibComAfterlogicPgpAesApi_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpAesApi, init)
}

LibComAfterlogicPgpAesApi *create_LibComAfterlogicPgpAesApi_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpAesApi, init)
}

IOSByteArray *LibComAfterlogicPgpAesApi_performCryptionWithByteArray_withNSString_withNSString_withJavaLangBoolean_withJavaLangBoolean_(IOSByteArray *fileData, NSString *rawKey, NSString *iv, JavaLangBoolean *isLast, JavaLangBoolean *isDecrypt) {
  LibComAfterlogicPgpAesApi_initialize();
  JavaxCryptoSpecSecretKeySpec *skeySpec = new_JavaxCryptoSpecSecretKeySpec_initWithByteArray_withNSString_(LibOrgBouncycastleUtilEncodersBase64_decodeWithNSString_(rawKey), @"AES");
  NSString *padding = [((JavaLangBoolean *) nil_chk(isLast)) booleanValue] ? @"PKCS5Padding" : @"NoPadding";
  JavaxCryptoCipher *cipher = JavaxCryptoCipher_getInstanceWithNSString_(JreStrcat("$$", @"AES/CBC/", padding));
  jint mode = [((JavaLangBoolean *) nil_chk(isDecrypt)) booleanValue] ? JavaxCryptoCipher_DECRYPT_MODE : JavaxCryptoCipher_ENCRYPT_MODE;
  [((JavaxCryptoCipher *) nil_chk(cipher)) init__WithInt:mode withJavaSecurityKey:skeySpec withJavaSecuritySpecAlgorithmParameterSpec:new_JavaxCryptoSpecIvParameterSpec_initWithByteArray_(LibOrgBouncycastleUtilEncodersBase64_decodeWithNSString_(iv))];
  return [cipher doFinalWithByteArray:fileData];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpAesApi)