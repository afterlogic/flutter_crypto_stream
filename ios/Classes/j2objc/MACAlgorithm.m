//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/MACAlgorithm.java
//

#include "J2ObjC_source.h"
#include "MACAlgorithm.h"

@implementation LibOrgBouncycastleCryptoTlsMACAlgorithm

+ (jint)_null {
  return LibOrgBouncycastleCryptoTlsMACAlgorithm__null;
}

+ (jint)md5 {
  return LibOrgBouncycastleCryptoTlsMACAlgorithm_md5;
}

+ (jint)sha {
  return LibOrgBouncycastleCryptoTlsMACAlgorithm_sha;
}

+ (jint)hmac_md5 {
  return LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_md5;
}

+ (jint)hmac_sha1 {
  return LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha1;
}

+ (jint)hmac_sha256 {
  return LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha256;
}

+ (jint)hmac_sha384 {
  return LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha384;
}

+ (jint)hmac_sha512 {
  return LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha512;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsMACAlgorithm_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_null", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsMACAlgorithm__null, 0x19, -1, -1, -1, -1 },
    { "md5", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsMACAlgorithm_md5, 0x19, -1, -1, -1, -1 },
    { "sha", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsMACAlgorithm_sha, 0x19, -1, -1, -1, -1 },
    { "hmac_md5", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_md5, 0x19, -1, -1, -1, -1 },
    { "hmac_sha1", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha1, 0x19, -1, -1, -1, -1 },
    { "hmac_sha256", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha256, 0x19, -1, -1, -1, -1 },
    { "hmac_sha384", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha384, 0x19, -1, -1, -1, -1 },
    { "hmac_sha512", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsMACAlgorithm_hmac_sha512, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsMACAlgorithm = { "MACAlgorithm", "lib.org.bouncycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsMACAlgorithm;
}

@end

void LibOrgBouncycastleCryptoTlsMACAlgorithm_init(LibOrgBouncycastleCryptoTlsMACAlgorithm *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsMACAlgorithm *new_LibOrgBouncycastleCryptoTlsMACAlgorithm_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsMACAlgorithm, init)
}

LibOrgBouncycastleCryptoTlsMACAlgorithm *create_LibOrgBouncycastleCryptoTlsMACAlgorithm_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsMACAlgorithm, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsMACAlgorithm)
