//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/ECKeyPairGenerator.java
//

#include "AsymmetricCipherKeyPair.h"
#include "BigIntegers.h"
#include "CryptoServicesRegistrar.h"
#include "ECConstants.h"
#include "ECDomainParameters.h"
#include "ECKeyGenerationParameters.h"
#include "ECKeyPairGenerator.h"
#include "ECMultiplier.h"
#include "ECPoint.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicKeyParameters.h"
#include "FixedPointCombMultiplier.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "WNafUtil.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@implementation LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param {
  LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *ecP = (LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsECKeyGenerationParameters class]);
  self->random_ = [((LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *) nil_chk(ecP)) getRandom];
  self->params_ = [ecP getDomainParameters];
  if (self->random_ == nil) {
    self->random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
  }
}

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  JavaMathBigInteger *n = [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(params_)) getN];
  jint nBitLength = [((JavaMathBigInteger *) nil_chk(n)) bitLength];
  jint minWeight = JreURShift32(nBitLength, 2);
  JavaMathBigInteger *d;
  for (; ; ) {
    d = LibOrgBouncycastleUtilBigIntegers_createRandomBigIntegerWithInt_withJavaSecuritySecureRandom_(nBitLength, random_);
    if ([((JavaMathBigInteger *) nil_chk(d)) compareToWithId:JreLoadStatic(LibOrgBouncycastleMathEcECConstants, TWO)] < 0 || ([d compareToWithId:n] >= 0)) {
      continue;
    }
    if (LibOrgBouncycastleMathEcWNafUtil_getNafWeightWithJavaMathBigInteger_(d) < minWeight) {
      continue;
    }
    break;
  }
  LibOrgBouncycastleMathEcECPoint *Q = [((id<LibOrgBouncycastleMathEcECMultiplier>) nil_chk([self createBasePointMultiplier])) multiplyWithLibOrgBouncycastleMathEcECPoint:[((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(params_)) getG] withJavaMathBigInteger:d];
  return new_LibOrgBouncycastleCryptoAsymmetricCipherKeyPair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(new_LibOrgBouncycastleCryptoParamsECPublicKeyParameters_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleCryptoParamsECDomainParameters_(Q, params_), new_LibOrgBouncycastleCryptoParamsECPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsECDomainParameters_(d, params_));
}

- (id<LibOrgBouncycastleMathEcECMultiplier>)createBasePointMultiplier {
  return new_LibOrgBouncycastleMathEcFixedPointCombMultiplier_init();
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECMultiplier;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKeyPair);
  methods[3].selector = @selector(createBasePointMultiplier);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastleCryptoParamsECDomainParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoKeyGenerationParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator = { "ECKeyPairGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator)