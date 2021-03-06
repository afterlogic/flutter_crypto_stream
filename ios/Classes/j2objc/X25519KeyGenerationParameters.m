//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/X25519KeyGenerationParameters.java
//

#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "X25519KeyGenerationParameters.h"
#include "java/security/SecureRandom.h"

@implementation LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters_initWithJavaSecuritySecureRandom_(self, random);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters = { "X25519KeyGenerationParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters;
}

@end

void LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters *self, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(self, random, 255);
}

LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters *new_LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters, initWithJavaSecuritySecureRandom_, random)
}

LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters *create_LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters, initWithJavaSecuritySecureRandom_, random)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsX25519KeyGenerationParameters)
