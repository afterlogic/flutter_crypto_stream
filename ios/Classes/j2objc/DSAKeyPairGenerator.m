//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/DSAKeyPairGenerator.java
//

#include "AsymmetricCipherKeyPair.h"
#include "BigIntegers.h"
#include "DSAKeyGenerationParameters.h"
#include "DSAKeyPairGenerator.h"
#include "DSAParameters.h"
#include "DSAPrivateKeyParameters.h"
#include "DSAPublicKeyParameters.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "WNafUtil.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator () {
 @public
  LibOrgBouncycastleCryptoParamsDSAKeyGenerationParameters *param_;
}

+ (JavaMathBigInteger *)generatePrivateKeyWithJavaMathBigInteger:(JavaMathBigInteger *)q
                                    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (JavaMathBigInteger *)calculatePublicKeyWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                          withJavaMathBigInteger:(JavaMathBigInteger *)g
                                          withJavaMathBigInteger:(JavaMathBigInteger *)x;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator, param_, LibOrgBouncycastleCryptoParamsDSAKeyGenerationParameters *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_get_ONE(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator, ONE, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_generatePrivateKeyWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *q, JavaSecuritySecureRandom *random);

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_calculatePublicKeyWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *x);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator)

@implementation LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param {
  self->param_ = (LibOrgBouncycastleCryptoParamsDSAKeyGenerationParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsDSAKeyGenerationParameters class]);
}

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  LibOrgBouncycastleCryptoParamsDSAParameters *dsaParams = [((LibOrgBouncycastleCryptoParamsDSAKeyGenerationParameters *) nil_chk(param_)) getParameters];
  JavaMathBigInteger *x = LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_generatePrivateKeyWithJavaMathBigInteger_withJavaSecuritySecureRandom_([((LibOrgBouncycastleCryptoParamsDSAParameters *) nil_chk(dsaParams)) getQ], [((LibOrgBouncycastleCryptoParamsDSAKeyGenerationParameters *) nil_chk(param_)) getRandom]);
  JavaMathBigInteger *y = LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_calculatePublicKeyWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([dsaParams getP], [dsaParams getG], x);
  return new_LibOrgBouncycastleCryptoAsymmetricCipherKeyPair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(new_LibOrgBouncycastleCryptoParamsDSAPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDSAParameters_(y, dsaParams), new_LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDSAParameters_(x, dsaParams));
}

+ (JavaMathBigInteger *)generatePrivateKeyWithJavaMathBigInteger:(JavaMathBigInteger *)q
                                    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_generatePrivateKeyWithJavaMathBigInteger_withJavaSecuritySecureRandom_(q, random);
}

+ (JavaMathBigInteger *)calculatePublicKeyWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                          withJavaMathBigInteger:(JavaMathBigInteger *)g
                                          withJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_calculatePublicKeyWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(p, g, x);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0xa, 2, 3, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0xa, 4, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKeyPair);
  methods[3].selector = @selector(generatePrivateKeyWithJavaMathBigInteger:withJavaSecuritySecureRandom:);
  methods[4].selector = @selector(calculatePublicKeyWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 6, -1, -1 },
    { "param_", "LLibOrgBouncycastleCryptoParamsDSAKeyGenerationParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoKeyGenerationParameters;", "generatePrivateKey", "LJavaMathBigInteger;LJavaSecuritySecureRandom;", "calculatePublicKey", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;", &LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_ONE };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator = { "DSAKeyPairGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator class]) {
    LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator)
  }
}

@end

void LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator, init)
}

JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_generatePrivateKeyWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *q, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_initialize();
  jint minWeight = JreURShift32([((JavaMathBigInteger *) nil_chk(q)) bitLength], 2);
  for (; ; ) {
    JavaMathBigInteger *x = LibOrgBouncycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_ONE, [q subtractWithJavaMathBigInteger:LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_ONE], random);
    if (LibOrgBouncycastleMathEcWNafUtil_getNafWeightWithJavaMathBigInteger_(x) >= minWeight) {
      return x;
    }
  }
}

JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_calculatePublicKeyWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *x) {
  LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator_initialize();
  return [((JavaMathBigInteger *) nil_chk(g)) modPowWithJavaMathBigInteger:x withJavaMathBigInteger:p];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsDSAKeyPairGenerator)
