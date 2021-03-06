//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/drbg/DualECPoints.java
//

#include "DualECPoints.h"
#include "ECCurve.h"
#include "ECPoint.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoPrngDrbgDualECPoints () {
 @public
  LibOrgBouncycastleMathEcECPoint *p_;
  LibOrgBouncycastleMathEcECPoint *q_;
  jint securityStrength_;
  jint cofactor_;
}

+ (jint)log2WithInt:(jint)value;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECPoints, p_, LibOrgBouncycastleMathEcECPoint *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECPoints, q_, LibOrgBouncycastleMathEcECPoint *)

__attribute__((unused)) static jint LibOrgBouncycastleCryptoPrngDrbgDualECPoints_log2WithInt_(jint value);

@implementation LibOrgBouncycastleCryptoPrngDrbgDualECPoints

- (instancetype)initWithInt:(jint)securityStrength
withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)q
                    withInt:(jint)cofactor {
  LibOrgBouncycastleCryptoPrngDrbgDualECPoints_initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_(self, securityStrength, p, q, cofactor);
  return self;
}

- (jint)getSeedLen {
  return [((LibOrgBouncycastleMathEcECCurve *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p_)) getCurve])) getFieldSize];
}

- (jint)getMaxOutlen {
  return (([((LibOrgBouncycastleMathEcECCurve *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p_)) getCurve])) getFieldSize] - (13 + LibOrgBouncycastleCryptoPrngDrbgDualECPoints_log2WithInt_(cofactor_))) / 8) * 8;
}

- (LibOrgBouncycastleMathEcECPoint *)getP {
  return p_;
}

- (LibOrgBouncycastleMathEcECPoint *)getQ {
  return q_;
}

- (jint)getSecurityStrength {
  return securityStrength_;
}

- (jint)getCofactor {
  return cofactor_;
}

+ (jint)log2WithInt:(jint)value {
  return LibOrgBouncycastleCryptoPrngDrbgDualECPoints_log2WithInt_(value);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0xa, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withLibOrgBouncycastleMathEcECPoint:withLibOrgBouncycastleMathEcECPoint:withInt:);
  methods[1].selector = @selector(getSeedLen);
  methods[2].selector = @selector(getMaxOutlen);
  methods[3].selector = @selector(getP);
  methods[4].selector = @selector(getQ);
  methods[5].selector = @selector(getSecurityStrength);
  methods[6].selector = @selector(getCofactor);
  methods[7].selector = @selector(log2WithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p_", "LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "q_", "LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "securityStrength_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "cofactor_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILLibOrgBouncycastleMathEcECPoint;LLibOrgBouncycastleMathEcECPoint;I", "log2", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPrngDrbgDualECPoints = { "DualECPoints", "lib.org.bouncycastle.crypto.prng.drbg", ptrTable, methods, fields, 7, 0x1, 8, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPrngDrbgDualECPoints;
}

@end

void LibOrgBouncycastleCryptoPrngDrbgDualECPoints_initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_(LibOrgBouncycastleCryptoPrngDrbgDualECPoints *self, jint securityStrength, LibOrgBouncycastleMathEcECPoint *p, LibOrgBouncycastleMathEcECPoint *q, jint cofactor) {
  NSObject_init(self);
  if (![((LibOrgBouncycastleMathEcECCurve *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getCurve])) equalsWithLibOrgBouncycastleMathEcECCurve:[((LibOrgBouncycastleMathEcECPoint *) nil_chk(q)) getCurve]]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"points need to be on the same curve");
  }
  self->securityStrength_ = securityStrength;
  self->p_ = p;
  self->q_ = q;
  self->cofactor_ = cofactor;
}

LibOrgBouncycastleCryptoPrngDrbgDualECPoints *new_LibOrgBouncycastleCryptoPrngDrbgDualECPoints_initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_(jint securityStrength, LibOrgBouncycastleMathEcECPoint *p, LibOrgBouncycastleMathEcECPoint *q, jint cofactor) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoPrngDrbgDualECPoints, initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_, securityStrength, p, q, cofactor)
}

LibOrgBouncycastleCryptoPrngDrbgDualECPoints *create_LibOrgBouncycastleCryptoPrngDrbgDualECPoints_initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_(jint securityStrength, LibOrgBouncycastleMathEcECPoint *p, LibOrgBouncycastleMathEcECPoint *q, jint cofactor) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoPrngDrbgDualECPoints, initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_, securityStrength, p, q, cofactor)
}

jint LibOrgBouncycastleCryptoPrngDrbgDualECPoints_log2WithInt_(jint value) {
  LibOrgBouncycastleCryptoPrngDrbgDualECPoints_initialize();
  jint log = 0;
  while ((JreRShiftAssignInt(&value, 1)) != 0) {
    log++;
  }
  return log;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPrngDrbgDualECPoints)
