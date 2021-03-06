//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/EphemeralKeyPairGenerator.java
//

#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricCipherKeyPairGenerator.h"
#include "EphemeralKeyPair.h"
#include "EphemeralKeyPairGenerator.h"
#include "J2ObjC_source.h"
#include "KeyEncoder.h"

@interface LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator () {
 @public
  id<LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator> gen_;
  id<LibOrgBouncycastleCryptoKeyEncoder> keyEncoder_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator, gen_, id<LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator, keyEncoder_, id<LibOrgBouncycastleCryptoKeyEncoder>)

@implementation LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator

- (instancetype)initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator:(id<LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator>)gen
                                          withLibOrgBouncycastleCryptoKeyEncoder:(id<LibOrgBouncycastleCryptoKeyEncoder>)keyEncoder {
  LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator_initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator_withLibOrgBouncycastleCryptoKeyEncoder_(self, gen, keyEncoder);
  return self;
}

- (LibOrgBouncycastleCryptoEphemeralKeyPair *)generate {
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *eph = [((id<LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator>) nil_chk(gen_)) generateKeyPair];
  return new_LibOrgBouncycastleCryptoEphemeralKeyPair_initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPair_withLibOrgBouncycastleCryptoKeyEncoder_(eph, keyEncoder_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoEphemeralKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator:withLibOrgBouncycastleCryptoKeyEncoder:);
  methods[1].selector = @selector(generate);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "gen_", "LLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyEncoder_", "LLibOrgBouncycastleCryptoKeyEncoder;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator;LLibOrgBouncycastleCryptoKeyEncoder;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator = { "EphemeralKeyPairGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator_initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator_withLibOrgBouncycastleCryptoKeyEncoder_(LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator *self, id<LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator> gen, id<LibOrgBouncycastleCryptoKeyEncoder> keyEncoder) {
  NSObject_init(self);
  self->gen_ = gen;
  self->keyEncoder_ = keyEncoder;
}

LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator_initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator_withLibOrgBouncycastleCryptoKeyEncoder_(id<LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator> gen, id<LibOrgBouncycastleCryptoKeyEncoder> keyEncoder) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator, initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator_withLibOrgBouncycastleCryptoKeyEncoder_, gen, keyEncoder)
}

LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator_initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator_withLibOrgBouncycastleCryptoKeyEncoder_(id<LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator> gen, id<LibOrgBouncycastleCryptoKeyEncoder> keyEncoder) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator, initWithLibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator_withLibOrgBouncycastleCryptoKeyEncoder_, gen, keyEncoder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsEphemeralKeyPairGenerator)
