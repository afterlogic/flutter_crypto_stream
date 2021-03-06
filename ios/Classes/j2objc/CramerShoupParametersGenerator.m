//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/CramerShoupParametersGenerator.java
//

#include "BigIntegers.h"
#include "CramerShoupParameters.h"
#include "CramerShoupParametersGenerator.h"
#include "DHParameters.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "SHA256Digest.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator () {
 @public
  jint size_;
  jint certainty_;
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator, random_, JavaSecuritySecureRandom *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_get_ONE(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator, ONE, JavaMathBigInteger *)

@interface LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper : NSObject

- (instancetype)init;

+ (IOSObjectArray *)generateSafePrimesWithInt:(jint)size
                                      withInt:(jint)certainty
                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (JavaMathBigInteger *)selectGeneratorWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_get_TWO(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper, TWO, JavaMathBigInteger *)

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *self);

__attribute__((unused)) static LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *new_LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *create_LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(void);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_generateSafePrimesWithInt_withInt_withJavaSecuritySecureRandom_(jint size, jint certainty, JavaSecuritySecureRandom *random);

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *p, JavaSecuritySecureRandom *random);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator)

@implementation LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithInt:(jint)size
              withInt:(jint)certainty
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->size_ = size;
  self->certainty_ = certainty;
  self->random_ = random;
}

- (LibOrgBouncycastleCryptoParamsCramerShoupParameters *)generateParameters {
  IOSObjectArray *safePrimes = LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_generateSafePrimesWithInt_withInt_withJavaSecuritySecureRandom_(size_, certainty_, random_);
  JavaMathBigInteger *q = IOSObjectArray_Get(nil_chk(safePrimes), 1);
  JavaMathBigInteger *g1 = LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(q, random_);
  JavaMathBigInteger *g2 = LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(q, random_);
  while ([((JavaMathBigInteger *) nil_chk(g1)) isEqual:g2]) {
    g2 = LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(q, random_);
  }
  return new_LibOrgBouncycastleCryptoParamsCramerShoupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoDigest_(q, g1, g2, new_LibOrgBouncycastleCryptoDigestsSHA256Digest_init());
}

- (LibOrgBouncycastleCryptoParamsCramerShoupParameters *)generateParametersWithLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)dhParams {
  JavaMathBigInteger *p = [((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(dhParams)) getP];
  JavaMathBigInteger *g1 = [dhParams getG];
  JavaMathBigInteger *g2 = LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(p, random_);
  while ([((JavaMathBigInteger *) nil_chk(g1)) isEqual:g2]) {
    g2 = LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(p, random_);
  }
  return new_LibOrgBouncycastleCryptoParamsCramerShoupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoDigest_(p, g1, g2, new_LibOrgBouncycastleCryptoDigestsSHA256Digest_init());
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsCramerShoupParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsCramerShoupParameters;", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithInt:withInt:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(generateParameters);
  methods[3].selector = @selector(generateParametersWithLibOrgBouncycastleCryptoParamsDHParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 4, -1, -1 },
    { "size_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certainty_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "IILJavaSecuritySecureRandom;", "generateParameters", "LLibOrgBouncycastleCryptoParamsDHParameters;", &LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ONE, "LLibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator = { "CramerShoupParametersGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 4, 4, -1, 5, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator class]) {
    LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator)
  }
}

@end

void LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_init(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)

@implementation LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSObjectArray *)generateSafePrimesWithInt:(jint)size
                                      withInt:(jint)certainty
                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_generateSafePrimesWithInt_withInt_withJavaSecuritySecureRandom_(size, certainty, random);
}

+ (JavaMathBigInteger *)selectGeneratorWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(p, random);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x8, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateSafePrimesWithInt:withInt:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(selectGeneratorWithJavaMathBigInteger:withJavaSecuritySecureRandom:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TWO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 4, -1, -1 },
  };
  static const void *ptrTable[] = { "generateSafePrimes", "IILJavaSecuritySecureRandom;", "selectGenerator", "LJavaMathBigInteger;LJavaSecuritySecureRandom;", &LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO, "LLibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper = { "ParametersHelper", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0xa, 3, 1, 5, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper class]) {
    LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO = JavaMathBigInteger_valueOfWithLong_(2);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)
  }
}

@end

void LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *new_LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper, init)
}

LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *create_LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper, init)
}

IOSObjectArray *LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_generateSafePrimesWithInt_withInt_withJavaSecuritySecureRandom_(jint size, jint certainty, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_initialize();
  JavaMathBigInteger *p;
  JavaMathBigInteger *q;
  jint qLength = size - 1;
  for (; ; ) {
    q = LibOrgBouncycastleUtilBigIntegers_createRandomPrimeWithInt_withInt_withJavaSecuritySecureRandom_(qLength, 2, random);
    p = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(q)) shiftLeftWithInt:1])) addWithJavaMathBigInteger:JreLoadStatic(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator, ONE)];
    if ([((JavaMathBigInteger *) nil_chk(p)) isProbablePrimeWithInt:certainty] && (certainty <= 2 || [q isProbablePrimeWithInt:certainty])) {
      break;
    }
  }
  return [IOSObjectArray newArrayWithObjects:(id[]){ p, q } count:2 type:JavaMathBigInteger_class_()];
}

JavaMathBigInteger *LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *p, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_initialize();
  JavaMathBigInteger *pMinusTwo = [((JavaMathBigInteger *) nil_chk(p)) subtractWithJavaMathBigInteger:LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO];
  JavaMathBigInteger *g;
  do {
    JavaMathBigInteger *h = LibOrgBouncycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO, pMinusTwo, random);
    g = [((JavaMathBigInteger *) nil_chk(h)) modPowWithJavaMathBigInteger:LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO withJavaMathBigInteger:p];
  }
  while ([((JavaMathBigInteger *) nil_chk(g)) isEqual:JreLoadStatic(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator, ONE)]);
  return g;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)
