//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/ElGamalKeyPairGenerator.java
//

#include "AsymmetricCipherKeyPair.h"
#include "DHKeyGeneratorHelper.h"
#include "DHParameters.h"
#include "ElGamalKeyGenerationParameters.h"
#include "ElGamalKeyPairGenerator.h"
#include "ElGamalParameters.h"
#include "ElGamalPrivateKeyParameters.h"
#include "ElGamalPublicKeyParameters.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator () {
 @public
  LibOrgBouncycastleCryptoParamsElGamalKeyGenerationParameters *param_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator, param_, LibOrgBouncycastleCryptoParamsElGamalKeyGenerationParameters *)

@implementation LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param {
  self->param_ = (LibOrgBouncycastleCryptoParamsElGamalKeyGenerationParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsElGamalKeyGenerationParameters class]);
}

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  LibOrgBouncycastleCryptoGeneratorsDHKeyGeneratorHelper *helper = JreLoadStatic(LibOrgBouncycastleCryptoGeneratorsDHKeyGeneratorHelper, INSTANCE);
  LibOrgBouncycastleCryptoParamsElGamalParameters *egp = [((LibOrgBouncycastleCryptoParamsElGamalKeyGenerationParameters *) nil_chk(param_)) getParameters];
  LibOrgBouncycastleCryptoParamsDHParameters *dhp = new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_([((LibOrgBouncycastleCryptoParamsElGamalParameters *) nil_chk(egp)) getP], [egp getG], nil, [egp getL]);
  JavaMathBigInteger *x = [((LibOrgBouncycastleCryptoGeneratorsDHKeyGeneratorHelper *) nil_chk(helper)) calculatePrivateWithLibOrgBouncycastleCryptoParamsDHParameters:dhp withJavaSecuritySecureRandom:[((LibOrgBouncycastleCryptoParamsElGamalKeyGenerationParameters *) nil_chk(param_)) getRandom]];
  JavaMathBigInteger *y = [helper calculatePublicWithLibOrgBouncycastleCryptoParamsDHParameters:dhp withJavaMathBigInteger:x];
  return new_LibOrgBouncycastleCryptoAsymmetricCipherKeyPair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(new_LibOrgBouncycastleCryptoParamsElGamalPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_(y, egp), new_LibOrgBouncycastleCryptoParamsElGamalPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsElGamalParameters_(x, egp));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKeyPair);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "param_", "LLibOrgBouncycastleCryptoParamsElGamalKeyGenerationParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoKeyGenerationParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator = { "ElGamalKeyPairGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsElGamalKeyPairGenerator)