//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/CryptoRSAKeyPairGenerator.java
//

#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricKeyParameter.h"
#include "BigIntegers.h"
#include "CryptoRSAKeyPairGenerator.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "Primes.h"
#include "RSAKeyGenerationParameters.h"
#include "RSAKeyParameters.h"
#include "RSAPrivateCrtKeyParameters.h"
#include "WNafUtil.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator () {
 @public
  LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters *param_;
}

+ (jint)getNumberOfIterationsWithInt:(jint)bits
                             withInt:(jint)certainty;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator, param_, LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_get_ONE(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator, ONE, JavaMathBigInteger *)

__attribute__((unused)) static jint LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_getNumberOfIterationsWithInt_withInt_(jint bits, jint certainty);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator)

@implementation LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param {
  self->param_ = (LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters class]);
}

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPairWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicParam
                                                                    withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateParam {
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *result = new_LibOrgBouncycastleCryptoAsymmetricCipherKeyPair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(publicParam, privateParam);
  return result;
}

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *result = nil;
  jboolean done = false;
  jint strength = [((LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters *) nil_chk(param_)) getStrength];
  jint pbitlength = (strength + 1) / 2;
  jint qbitlength = strength - pbitlength;
  jint mindiffbits = (strength / 2) - 100;
  if (mindiffbits < strength / 3) {
    mindiffbits = strength / 3;
  }
  jint minWeight = JreRShift32(strength, 2);
  JavaMathBigInteger *dLowerBound = [((JavaMathBigInteger *) nil_chk(JavaMathBigInteger_valueOfWithLong_(2))) powWithInt:strength / 2];
  JavaMathBigInteger *squaredBound = [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE)) shiftLeftWithInt:strength - 1];
  JavaMathBigInteger *minDiff = [LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE shiftLeftWithInt:mindiffbits];
  while (!done) {
    JavaMathBigInteger *p;
    JavaMathBigInteger *q;
    JavaMathBigInteger *n;
    JavaMathBigInteger *d;
    JavaMathBigInteger *e;
    JavaMathBigInteger *pSub1;
    JavaMathBigInteger *qSub1;
    JavaMathBigInteger *gcd;
    JavaMathBigInteger *lcm;
    e = [((LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters *) nil_chk(param_)) getPublicExponent];
    p = [self chooseRandomPrimeWithInt:pbitlength withJavaMathBigInteger:e withJavaMathBigInteger:squaredBound];
    for (; ; ) {
      q = [self chooseRandomPrimeWithInt:qbitlength withJavaMathBigInteger:e withJavaMathBigInteger:squaredBound];
      JavaMathBigInteger *diff = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(q)) subtractWithJavaMathBigInteger:p])) abs];
      if ([((JavaMathBigInteger *) nil_chk(diff)) bitLength] < mindiffbits || [diff compareToWithId:minDiff] <= 0) {
        continue;
      }
      n = [((JavaMathBigInteger *) nil_chk(p)) multiplyWithJavaMathBigInteger:q];
      if ([((JavaMathBigInteger *) nil_chk(n)) bitLength] != strength) {
        p = [p maxWithJavaMathBigInteger:q];
        continue;
      }
      if (LibOrgBouncycastleMathEcWNafUtil_getNafWeightWithJavaMathBigInteger_(n) < minWeight) {
        p = [self chooseRandomPrimeWithInt:pbitlength withJavaMathBigInteger:e withJavaMathBigInteger:squaredBound];
        continue;
      }
      break;
    }
    if ([p compareToWithId:q] < 0) {
      gcd = p;
      p = q;
      q = gcd;
    }
    pSub1 = [p subtractWithJavaMathBigInteger:LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE];
    qSub1 = [q subtractWithJavaMathBigInteger:LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE];
    gcd = [((JavaMathBigInteger *) nil_chk(pSub1)) gcdWithJavaMathBigInteger:qSub1];
    lcm = [((JavaMathBigInteger *) nil_chk([pSub1 divideWithJavaMathBigInteger:gcd])) multiplyWithJavaMathBigInteger:qSub1];
    d = [((JavaMathBigInteger *) nil_chk(e)) modInverseWithJavaMathBigInteger:lcm];
    if ([((JavaMathBigInteger *) nil_chk(d)) compareToWithId:dLowerBound] <= 0) {
      continue;
    }
    else {
      done = true;
    }
    JavaMathBigInteger *dP;
    JavaMathBigInteger *dQ;
    JavaMathBigInteger *qInv;
    dP = [d remainderWithJavaMathBigInteger:pSub1];
    dQ = [d remainderWithJavaMathBigInteger:qSub1];
    qInv = [q modInverseWithJavaMathBigInteger:p];
    result = new_LibOrgBouncycastleCryptoAsymmetricCipherKeyPair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(new_LibOrgBouncycastleCryptoParamsRSAKeyParameters_initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_(false, n, e), new_LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(n, e, d, p, q, dP, dQ, qInv));
  }
  return result;
}

- (JavaMathBigInteger *)chooseRandomPrimeWithInt:(jint)bitlength
                          withJavaMathBigInteger:(JavaMathBigInteger *)e
                          withJavaMathBigInteger:(JavaMathBigInteger *)sqrdBound {
  for (jint i = 0; i != 5 * bitlength; i++) {
    JavaMathBigInteger *p = LibOrgBouncycastleUtilBigIntegers_createRandomPrimeWithInt_withInt_withJavaSecuritySecureRandom_(bitlength, 1, [((LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters *) nil_chk(param_)) getRandom]);
    if ([((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(p)) modWithJavaMathBigInteger:e])) isEqual:LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE]) {
      continue;
    }
    if ([((JavaMathBigInteger *) nil_chk([p multiplyWithJavaMathBigInteger:p])) compareToWithId:sqrdBound] < 0) {
      continue;
    }
    if (![self isProbablePrimeWithJavaMathBigInteger:p]) {
      continue;
    }
    if (![((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(e)) gcdWithJavaMathBigInteger:[p subtractWithJavaMathBigInteger:LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE]])) isEqual:LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE]) {
      continue;
    }
    return p;
  }
  @throw new_JavaLangIllegalStateException_initWithNSString_(@"unable to generate prime number for RSA key");
}

- (jboolean)isProbablePrimeWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  jint iterations = LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_getNumberOfIterationsWithInt_withInt_([((JavaMathBigInteger *) nil_chk(x)) bitLength], [((LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters *) nil_chk(param_)) getCertainty]);
  return !LibOrgBouncycastleMathPrimes_hasAnySmallFactorsWithJavaMathBigInteger_(x) && LibOrgBouncycastleMathPrimes_isMRProbablePrimeWithJavaMathBigInteger_withJavaSecuritySecureRandom_withInt_(x, [((LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters *) nil_chk(param_)) getRandom], iterations);
}

+ (jint)getNumberOfIterationsWithInt:(jint)bits
                             withInt:(jint)certainty {
  return LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_getNumberOfIterationsWithInt_withInt_(bits, certainty);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoAsymmetricCipherKeyPair;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 6, 7, -1, -1, -1, -1 },
    { NULL, "I", 0xa, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKeyPairWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[3].selector = @selector(generateKeyPair);
  methods[4].selector = @selector(chooseRandomPrimeWithInt:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[5].selector = @selector(isProbablePrimeWithJavaMathBigInteger:);
  methods[6].selector = @selector(getNumberOfIterationsWithInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 10, -1, -1 },
    { "param_", "LLibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoKeyGenerationParameters;", "generateKeyPair", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "chooseRandomPrime", "ILJavaMathBigInteger;LJavaMathBigInteger;", "isProbablePrime", "LJavaMathBigInteger;", "getNumberOfIterations", "II", &LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator = { "CryptoRSAKeyPairGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator class]) {
    LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator)
  }
}

@end

void LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator, init)
}

jint LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_getNumberOfIterationsWithInt_withInt_(jint bits, jint certainty) {
  LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_initialize();
  if (bits >= 1536) {
    return certainty <= 100 ? 3 : certainty <= 128 ? 4 : 4 + (certainty - 128 + 1) / 2;
  }
  else if (bits >= 1024) {
    return certainty <= 100 ? 4 : certainty <= 112 ? 5 : 5 + (certainty - 112 + 1) / 2;
  }
  else if (bits >= 512) {
    return certainty <= 80 ? 5 : certainty <= 100 ? 7 : 7 + (certainty - 100 + 1) / 2;
  }
  else {
    return certainty <= 80 ? 40 : 40 + (certainty - 80 + 1) / 2;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator)
