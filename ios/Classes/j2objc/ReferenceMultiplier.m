//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ReferenceMultiplier.java
//

#include "AbstractECMultiplier.h"
#include "ECAlgorithms.h"
#include "ECPoint.h"
#include "J2ObjC_source.h"
#include "ReferenceMultiplier.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleMathEcReferenceMultiplier

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcReferenceMultiplier_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECPoint *)multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                  withJavaMathBigInteger:(JavaMathBigInteger *)k {
  return LibOrgBouncycastleMathEcECAlgorithms_referenceMultiplyWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(p, k);
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
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcReferenceMultiplier = { "ReferenceMultiplier", "lib.org.bouncycastle.math.ec", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcReferenceMultiplier;
}

@end

void LibOrgBouncycastleMathEcReferenceMultiplier_init(LibOrgBouncycastleMathEcReferenceMultiplier *self) {
  LibOrgBouncycastleMathEcAbstractECMultiplier_init(self);
}

LibOrgBouncycastleMathEcReferenceMultiplier *new_LibOrgBouncycastleMathEcReferenceMultiplier_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcReferenceMultiplier, init)
}

LibOrgBouncycastleMathEcReferenceMultiplier *create_LibOrgBouncycastleMathEcReferenceMultiplier_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcReferenceMultiplier, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcReferenceMultiplier)
