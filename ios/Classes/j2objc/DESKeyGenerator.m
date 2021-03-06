//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/DESKeyGenerator.java
//

#include "CipherKeyGenerator.h"
#include "DESKeyGenerator.h"
#include "DESParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/SecureRandom.h"

@implementation LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param {
  [super init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param];
  if (strength_ == 0 || strength_ == (56 / 8)) {
    strength_ = LibOrgBouncycastleCryptoParamsDESParameters_DES_KEY_LENGTH;
  }
  else if (strength_ != LibOrgBouncycastleCryptoParamsDESParameters_DES_KEY_LENGTH) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I$", @"DES key must be ", (LibOrgBouncycastleCryptoParamsDESParameters_DES_KEY_LENGTH * 8), @" bits long."));
  }
}

- (IOSByteArray *)generateKey {
  IOSByteArray *newKey = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsDESParameters_DES_KEY_LENGTH];
  do {
    [((JavaSecuritySecureRandom *) nil_chk(random_)) nextBytesWithByteArray:newKey];
    LibOrgBouncycastleCryptoParamsDESParameters_setOddParityWithByteArray_(newKey);
  }
  while (LibOrgBouncycastleCryptoParamsDESParameters_isWeakKeyWithByteArray_withInt_(newKey, 0));
  return newKey;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKey);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoKeyGenerationParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator = { "DESKeyGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator_init(LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator *self) {
  LibOrgBouncycastleCryptoCipherKeyGenerator_init(self);
}

LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator *new_LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator *create_LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator)
