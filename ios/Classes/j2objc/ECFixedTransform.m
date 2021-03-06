//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/ec/ECFixedTransform.java
//

#include "CipherParameters.h"
#include "ECAlgorithms.h"
#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECFixedTransform.h"
#include "ECMultiplier.h"
#include "ECPair.h"
#include "ECPoint.h"
#include "ECPublicKeyParameters.h"
#include "FixedPointCombMultiplier.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoEcECFixedTransform () {
 @public
  LibOrgBouncycastleCryptoParamsECPublicKeyParameters *key_;
  JavaMathBigInteger *k_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEcECFixedTransform, key_, LibOrgBouncycastleCryptoParamsECPublicKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEcECFixedTransform, k_, JavaMathBigInteger *)

@implementation LibOrgBouncycastleCryptoEcECFixedTransform

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)k {
  LibOrgBouncycastleCryptoEcECFixedTransform_initWithJavaMathBigInteger_(self, k);
  return self;
}

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  if (!([param isKindOfClass:[LibOrgBouncycastleCryptoParamsECPublicKeyParameters class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"ECPublicKeyParameters are required for fixed transform.");
  }
  self->key_ = (LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsECPublicKeyParameters class]);
}

- (LibOrgBouncycastleCryptoEcECPair *)transformWithLibOrgBouncycastleCryptoEcECPair:(LibOrgBouncycastleCryptoEcECPair *)cipherText {
  if (key_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"ECFixedTransform not initialised");
  }
  LibOrgBouncycastleCryptoParamsECDomainParameters *ec = [key_ getParameters];
  JavaMathBigInteger *n = [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(ec)) getN];
  id<LibOrgBouncycastleMathEcECMultiplier> basePointMultiplier = [self createBasePointMultiplier];
  JavaMathBigInteger *k = [((JavaMathBigInteger *) nil_chk(self->k_)) modWithJavaMathBigInteger:n];
  IOSObjectArray *gamma_phi = [IOSObjectArray newArrayWithObjects:(id[]){ [((LibOrgBouncycastleMathEcECPoint *) nil_chk([((id<LibOrgBouncycastleMathEcECMultiplier>) nil_chk(basePointMultiplier)) multiplyWithLibOrgBouncycastleMathEcECPoint:[ec getG] withJavaMathBigInteger:k])) addWithLibOrgBouncycastleMathEcECPoint:LibOrgBouncycastleMathEcECAlgorithms_cleanPointWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_([ec getCurve], [((LibOrgBouncycastleCryptoEcECPair *) nil_chk(cipherText)) getX])], [((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) nil_chk(key_)) getQ])) multiplyWithJavaMathBigInteger:k])) addWithLibOrgBouncycastleMathEcECPoint:LibOrgBouncycastleMathEcECAlgorithms_cleanPointWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_([ec getCurve], [cipherText getY])] } count:2 type:LibOrgBouncycastleMathEcECPoint_class_()];
  [((LibOrgBouncycastleMathEcECCurve *) nil_chk([ec getCurve])) normalizeAllWithLibOrgBouncycastleMathEcECPointArray:gamma_phi];
  return new_LibOrgBouncycastleCryptoEcECPair_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_(IOSObjectArray_Get(gamma_phi, 0), IOSObjectArray_Get(gamma_phi, 1));
}

- (JavaMathBigInteger *)getTransformValue {
  return k_;
}

- (id<LibOrgBouncycastleMathEcECMultiplier>)createBasePointMultiplier {
  return new_LibOrgBouncycastleMathEcFixedPointCombMultiplier_init();
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoEcECPair;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECMultiplier;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(transformWithLibOrgBouncycastleCryptoEcECPair:);
  methods[3].selector = @selector(getTransformValue);
  methods[4].selector = @selector(createBasePointMultiplier);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "key_", "LLibOrgBouncycastleCryptoParamsECPublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "k_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;", "init", "LLibOrgBouncycastleCryptoCipherParameters;", "transform", "LLibOrgBouncycastleCryptoEcECPair;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEcECFixedTransform = { "ECFixedTransform", "lib.org.bouncycastle.crypto.ec", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEcECFixedTransform;
}

@end

void LibOrgBouncycastleCryptoEcECFixedTransform_initWithJavaMathBigInteger_(LibOrgBouncycastleCryptoEcECFixedTransform *self, JavaMathBigInteger *k) {
  NSObject_init(self);
  self->k_ = k;
}

LibOrgBouncycastleCryptoEcECFixedTransform *new_LibOrgBouncycastleCryptoEcECFixedTransform_initWithJavaMathBigInteger_(JavaMathBigInteger *k) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEcECFixedTransform, initWithJavaMathBigInteger_, k)
}

LibOrgBouncycastleCryptoEcECFixedTransform *create_LibOrgBouncycastleCryptoEcECFixedTransform_initWithJavaMathBigInteger_(JavaMathBigInteger *k) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEcECFixedTransform, initWithJavaMathBigInteger_, k)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEcECFixedTransform)
