//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ZSignedDigitR2LMultiplier.java
//

#include "AbstractECMultiplier.h"
#include "ECCurve.h"
#include "ECPoint.h"
#include "J2ObjC_source.h"
#include "ZSignedDigitR2LMultiplier.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECPoint *)multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                  withJavaMathBigInteger:(JavaMathBigInteger *)k {
  LibOrgBouncycastleMathEcECPoint *R0 = [((LibOrgBouncycastleMathEcECCurve *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getCurve])) getInfinity];
  LibOrgBouncycastleMathEcECPoint *R1 = p;
  jint n = [((JavaMathBigInteger *) nil_chk(k)) bitLength];
  jint s = [k getLowestSetBit];
  R1 = [R1 timesPow2WithInt:s];
  jint i = s;
  while (++i < n) {
    R0 = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(R0)) addWithLibOrgBouncycastleMathEcECPoint:[k testBitWithInt:i] ? R1 : [((LibOrgBouncycastleMathEcECPoint *) nil_chk(R1)) negate]];
    R1 = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(R1)) twice];
  }
  R0 = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(R0)) addWithLibOrgBouncycastleMathEcECPoint:R1];
  return R0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "multiplyPositive", "LLibOrgBouncycastleMathEcECPoint;LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier = { "ZSignedDigitR2LMultiplier", "lib.org.bouncycastle.math.ec", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier;
}

@end

void LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier_init(LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier *self) {
  LibOrgBouncycastleMathEcAbstractECMultiplier_init(self);
}

LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier *new_LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier, init)
}

LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier *create_LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcZSignedDigitR2LMultiplier)
