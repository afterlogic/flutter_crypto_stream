//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/DSTU4145Signer.java
//

#include "Arrays.h"
#include "BigIntegers.h"
#include "CipherParameters.h"
#include "CryptoServicesRegistrar.h"
#include "DSTU4145Signer.h"
#include "ECAlgorithms.h"
#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECFieldElement.h"
#include "ECKeyParameters.h"
#include "ECMultiplier.h"
#include "ECPoint.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicKeyParameters.h"
#include "FixedPointCombMultiplier.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithRandom.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoSignersDSTU4145Signer () {
 @public
  LibOrgBouncycastleCryptoParamsECKeyParameters *key_;
  JavaSecuritySecureRandom *random_;
}

+ (JavaMathBigInteger *)generateRandomIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (LibOrgBouncycastleMathEcECFieldElement *)hash2FieldElementWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                                                                                   withByteArray:(IOSByteArray *)hash_;

+ (JavaMathBigInteger *)fieldElement2IntegerWithJavaMathBigInteger:(JavaMathBigInteger *)n
                        withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)fe;

+ (JavaMathBigInteger *)truncateWithJavaMathBigInteger:(JavaMathBigInteger *)x
                                               withInt:(jint)bitLength;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersDSTU4145Signer, key_, LibOrgBouncycastleCryptoParamsECKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersDSTU4145Signer, random_, JavaSecuritySecureRandom *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoSignersDSTU4145Signer_get_ONE(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoSignersDSTU4145Signer_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoSignersDSTU4145Signer, ONE, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoSignersDSTU4145Signer_generateRandomIntegerWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *n, JavaSecuritySecureRandom *random);

__attribute__((unused)) static LibOrgBouncycastleMathEcECFieldElement *LibOrgBouncycastleCryptoSignersDSTU4145Signer_hash2FieldElementWithLibOrgBouncycastleMathEcECCurve_withByteArray_(LibOrgBouncycastleMathEcECCurve *curve, IOSByteArray *hash_);

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoSignersDSTU4145Signer_fieldElement2IntegerWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_(JavaMathBigInteger *n, LibOrgBouncycastleMathEcECFieldElement *fe);

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoSignersDSTU4145Signer_truncateWithJavaMathBigInteger_withInt_(JavaMathBigInteger *x, jint bitLength);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoSignersDSTU4145Signer)

@implementation LibOrgBouncycastleCryptoSignersDSTU4145Signer

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoSignersDSTU4145Signer_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  if (forSigning) {
    if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
      LibOrgBouncycastleCryptoParamsParametersWithRandom *rParam = (LibOrgBouncycastleCryptoParamsParametersWithRandom *) param;
      self->random_ = [((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getRandom];
      param = [rParam getParameters];
    }
    else {
      self->random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
    }
    self->key_ = (LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class]);
  }
  else {
    self->key_ = (LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsECPublicKeyParameters class]);
  }
}

- (JavaMathBigInteger *)getOrder {
  return [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsECKeyParameters *) nil_chk(key_)) getParameters])) getN];
}

- (IOSObjectArray *)generateSignatureWithByteArray:(IOSByteArray *)message {
  LibOrgBouncycastleCryptoParamsECDomainParameters *ec = [((LibOrgBouncycastleCryptoParamsECKeyParameters *) nil_chk(key_)) getParameters];
  LibOrgBouncycastleMathEcECCurve *curve = [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(ec)) getCurve];
  LibOrgBouncycastleMathEcECFieldElement *h = LibOrgBouncycastleCryptoSignersDSTU4145Signer_hash2FieldElementWithLibOrgBouncycastleMathEcECCurve_withByteArray_(curve, message);
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(h)) isZero]) {
    h = [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) fromBigIntegerWithJavaMathBigInteger:LibOrgBouncycastleCryptoSignersDSTU4145Signer_ONE];
  }
  JavaMathBigInteger *n = [ec getN];
  JavaMathBigInteger *e;
  JavaMathBigInteger *r;
  JavaMathBigInteger *s;
  LibOrgBouncycastleMathEcECFieldElement *Fe;
  LibOrgBouncycastleMathEcECFieldElement *y;
  JavaMathBigInteger *d = [((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) cast_chk(key_, [LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class])))) getD];
  id<LibOrgBouncycastleMathEcECMultiplier> basePointMultiplier = [self createBasePointMultiplier];
  do {
    do {
      do {
        e = LibOrgBouncycastleCryptoSignersDSTU4145Signer_generateRandomIntegerWithJavaMathBigInteger_withJavaSecuritySecureRandom_(n, random_);
        Fe = [((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([((id<LibOrgBouncycastleMathEcECMultiplier>) nil_chk(basePointMultiplier)) multiplyWithLibOrgBouncycastleMathEcECPoint:[ec getG] withJavaMathBigInteger:e])) normalize])) getAffineXCoord];
      }
      while ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Fe)) isZero]);
      y = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(h)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Fe];
      r = LibOrgBouncycastleCryptoSignersDSTU4145Signer_fieldElement2IntegerWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_(n, y);
    }
    while ([((JavaMathBigInteger *) nil_chk(r)) signum] == 0);
    s = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([r multiplyWithJavaMathBigInteger:d])) addWithJavaMathBigInteger:e])) modWithJavaMathBigInteger:n];
  }
  while ([((JavaMathBigInteger *) nil_chk(s)) signum] == 0);
  return [IOSObjectArray newArrayWithObjects:(id[]){ r, s } count:2 type:JavaMathBigInteger_class_()];
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                  withJavaMathBigInteger:(JavaMathBigInteger *)r
                  withJavaMathBigInteger:(JavaMathBigInteger *)s {
  if ([((JavaMathBigInteger *) nil_chk(r)) signum] <= 0 || [((JavaMathBigInteger *) nil_chk(s)) signum] <= 0) {
    return false;
  }
  LibOrgBouncycastleCryptoParamsECDomainParameters *parameters = [((LibOrgBouncycastleCryptoParamsECKeyParameters *) nil_chk(key_)) getParameters];
  JavaMathBigInteger *n = [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(parameters)) getN];
  if ([r compareToWithId:n] >= 0 || [((JavaMathBigInteger *) nil_chk(s)) compareToWithId:n] >= 0) {
    return false;
  }
  LibOrgBouncycastleMathEcECCurve *curve = [parameters getCurve];
  LibOrgBouncycastleMathEcECFieldElement *h = LibOrgBouncycastleCryptoSignersDSTU4145Signer_hash2FieldElementWithLibOrgBouncycastleMathEcECCurve_withByteArray_(curve, message);
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(h)) isZero]) {
    h = [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) fromBigIntegerWithJavaMathBigInteger:LibOrgBouncycastleCryptoSignersDSTU4145Signer_ONE];
  }
  LibOrgBouncycastleMathEcECPoint *R = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(LibOrgBouncycastleMathEcECAlgorithms_sumOfTwoMultipliesWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_([parameters getG], s, [((LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) nil_chk(((LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) cast_chk(key_, [LibOrgBouncycastleCryptoParamsECPublicKeyParameters class])))) getQ], r))) normalize];
  if ([((LibOrgBouncycastleMathEcECPoint *) nil_chk(R)) isInfinity]) {
    return false;
  }
  LibOrgBouncycastleMathEcECFieldElement *y = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(h)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:[R getAffineXCoord]];
  return [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleCryptoSignersDSTU4145Signer_fieldElement2IntegerWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_(n, y))) compareToWithId:r] == 0;
}

- (id<LibOrgBouncycastleMathEcECMultiplier>)createBasePointMultiplier {
  return new_LibOrgBouncycastleMathEcFixedPointCombMultiplier_init();
}

+ (JavaMathBigInteger *)generateRandomIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleCryptoSignersDSTU4145Signer_generateRandomIntegerWithJavaMathBigInteger_withJavaSecuritySecureRandom_(n, random);
}

+ (LibOrgBouncycastleMathEcECFieldElement *)hash2FieldElementWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                                                                                   withByteArray:(IOSByteArray *)hash_ {
  return LibOrgBouncycastleCryptoSignersDSTU4145Signer_hash2FieldElementWithLibOrgBouncycastleMathEcECCurve_withByteArray_(curve, hash_);
}

+ (JavaMathBigInteger *)fieldElement2IntegerWithJavaMathBigInteger:(JavaMathBigInteger *)n
                        withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)fe {
  return LibOrgBouncycastleCryptoSignersDSTU4145Signer_fieldElement2IntegerWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_(n, fe);
}

+ (JavaMathBigInteger *)truncateWithJavaMathBigInteger:(JavaMathBigInteger *)x
                                               withInt:(jint)bitLength {
  return LibOrgBouncycastleCryptoSignersDSTU4145Signer_truncateWithJavaMathBigInteger_withInt_(x, bitLength);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECMultiplier;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0xa, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0xa, 8, 9, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0xa, 10, 11, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0xa, 12, 13, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getOrder);
  methods[3].selector = @selector(generateSignatureWithByteArray:);
  methods[4].selector = @selector(verifySignatureWithByteArray:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[5].selector = @selector(createBasePointMultiplier);
  methods[6].selector = @selector(generateRandomIntegerWithJavaMathBigInteger:withJavaSecuritySecureRandom:);
  methods[7].selector = @selector(hash2FieldElementWithLibOrgBouncycastleMathEcECCurve:withByteArray:);
  methods[8].selector = @selector(fieldElement2IntegerWithJavaMathBigInteger:withLibOrgBouncycastleMathEcECFieldElement:);
  methods[9].selector = @selector(truncateWithJavaMathBigInteger:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 14, -1, -1 },
    { "key_", "LLibOrgBouncycastleCryptoParamsECKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "generateSignature", "[B", "verifySignature", "[BLJavaMathBigInteger;LJavaMathBigInteger;", "generateRandomInteger", "LJavaMathBigInteger;LJavaSecuritySecureRandom;", "hash2FieldElement", "LLibOrgBouncycastleMathEcECCurve;[B", "fieldElement2Integer", "LJavaMathBigInteger;LLibOrgBouncycastleMathEcECFieldElement;", "truncate", "LJavaMathBigInteger;I", &LibOrgBouncycastleCryptoSignersDSTU4145Signer_ONE };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersDSTU4145Signer = { "DSTU4145Signer", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersDSTU4145Signer;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoSignersDSTU4145Signer class]) {
    LibOrgBouncycastleCryptoSignersDSTU4145Signer_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoSignersDSTU4145Signer)
  }
}

@end

void LibOrgBouncycastleCryptoSignersDSTU4145Signer_init(LibOrgBouncycastleCryptoSignersDSTU4145Signer *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoSignersDSTU4145Signer *new_LibOrgBouncycastleCryptoSignersDSTU4145Signer_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersDSTU4145Signer, init)
}

LibOrgBouncycastleCryptoSignersDSTU4145Signer *create_LibOrgBouncycastleCryptoSignersDSTU4145Signer_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersDSTU4145Signer, init)
}

JavaMathBigInteger *LibOrgBouncycastleCryptoSignersDSTU4145Signer_generateRandomIntegerWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *n, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoSignersDSTU4145Signer_initialize();
  return LibOrgBouncycastleUtilBigIntegers_createRandomBigIntegerWithInt_withJavaSecuritySecureRandom_([((JavaMathBigInteger *) nil_chk(n)) bitLength] - 1, random);
}

LibOrgBouncycastleMathEcECFieldElement *LibOrgBouncycastleCryptoSignersDSTU4145Signer_hash2FieldElementWithLibOrgBouncycastleMathEcECCurve_withByteArray_(LibOrgBouncycastleMathEcECCurve *curve, IOSByteArray *hash_) {
  LibOrgBouncycastleCryptoSignersDSTU4145Signer_initialize();
  IOSByteArray *data = LibOrgBouncycastleUtilArrays_reverseWithByteArray_(hash_);
  return [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) fromBigIntegerWithJavaMathBigInteger:LibOrgBouncycastleCryptoSignersDSTU4145Signer_truncateWithJavaMathBigInteger_withInt_(new_JavaMathBigInteger_initWithInt_withByteArray_(1, data), [curve getFieldSize])];
}

JavaMathBigInteger *LibOrgBouncycastleCryptoSignersDSTU4145Signer_fieldElement2IntegerWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_(JavaMathBigInteger *n, LibOrgBouncycastleMathEcECFieldElement *fe) {
  LibOrgBouncycastleCryptoSignersDSTU4145Signer_initialize();
  return LibOrgBouncycastleCryptoSignersDSTU4145Signer_truncateWithJavaMathBigInteger_withInt_([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(fe)) toBigInteger], [((JavaMathBigInteger *) nil_chk(n)) bitLength] - 1);
}

JavaMathBigInteger *LibOrgBouncycastleCryptoSignersDSTU4145Signer_truncateWithJavaMathBigInteger_withInt_(JavaMathBigInteger *x, jint bitLength) {
  LibOrgBouncycastleCryptoSignersDSTU4145Signer_initialize();
  if ([((JavaMathBigInteger *) nil_chk(x)) bitLength] > bitLength) {
    x = [x modWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleCryptoSignersDSTU4145Signer_ONE)) shiftLeftWithInt:bitLength]];
  }
  return x;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersDSTU4145Signer)
