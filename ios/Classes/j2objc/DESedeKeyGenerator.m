//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/DESedeKeyGenerator.java
//

#include "DESKeyGenerator.h"
#include "DESParameters.h"
#include "DESedeKeyGenerator.h"
#include "DESedeParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/security/SecureRandom.h"

inline jint LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_get_MAX_IT(void);
#define LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_MAX_IT 20
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator, MAX_IT, jint)

@implementation LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param {
  self->random_ = [((LibOrgBouncycastleCryptoKeyGenerationParameters *) nil_chk(param)) getRandom];
  self->strength_ = ([param getStrength] + 7) / 8;
  if (strength_ == 0 || strength_ == (168 / 8)) {
    strength_ = LibOrgBouncycastleCryptoParamsDESedeParameters_DES_EDE_KEY_LENGTH;
  }
  else if (strength_ == (112 / 8)) {
    strength_ = 2 * LibOrgBouncycastleCryptoParamsDESParameters_DES_KEY_LENGTH;
  }
  else if (strength_ != LibOrgBouncycastleCryptoParamsDESedeParameters_DES_EDE_KEY_LENGTH && strength_ != (2 * LibOrgBouncycastleCryptoParamsDESParameters_DES_KEY_LENGTH)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I$I$", @"DESede key must be ", (LibOrgBouncycastleCryptoParamsDESedeParameters_DES_EDE_KEY_LENGTH * 8), @" or ", (2 * 8 * LibOrgBouncycastleCryptoParamsDESParameters_DES_KEY_LENGTH), @" bits long."));
  }
}

- (IOSByteArray *)generateKey {
  IOSByteArray *newKey = [IOSByteArray newArrayWithLength:strength_];
  jint count = 0;
  do {
    [((JavaSecuritySecureRandom *) nil_chk(random_)) nextBytesWithByteArray:newKey];
    LibOrgBouncycastleCryptoParamsDESParameters_setOddParityWithByteArray_(newKey);
  }
  while (++count < LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_MAX_IT && (LibOrgBouncycastleCryptoParamsDESedeParameters_isWeakKeyWithByteArray_withInt_withInt_(newKey, 0, newKey->size_) || !LibOrgBouncycastleCryptoParamsDESedeParameters_isRealEDEKeyWithByteArray_withInt_(newKey, 0)));
  if (LibOrgBouncycastleCryptoParamsDESedeParameters_isWeakKeyWithByteArray_withInt_withInt_(newKey, 0, newKey->size_) || !LibOrgBouncycastleCryptoParamsDESedeParameters_isRealEDEKeyWithByteArray_withInt_(newKey, 0)) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Unable to generate DES-EDE key");
  }
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
  static const J2ObjcFieldInfo fields[] = {
    { "MAX_IT", "I", .constantValue.asInt = LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_MAX_IT, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoKeyGenerationParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator = { "DESedeKeyGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_init(LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator *self) {
  LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator_init(self);
}

LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator *new_LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator *create_LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator)
