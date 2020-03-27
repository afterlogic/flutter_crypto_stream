//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/generation/type/ECDH.java
//

#include "ECDH.h"
#include "ECNamedCurveGenParameterSpec.h"
#include "EllipticCurve.h"
#include "J2ObjC_source.h"
#include "PublicKeyAlgorithm.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibComAfterlogicPgpKeyGenerationTypeECDH () {
 @public
  LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *curve_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyGenerationTypeECDH, curve_, LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *)

@implementation LibComAfterlogicPgpKeyGenerationTypeECDH

- (instancetype)initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve:(LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *)curve {
  LibComAfterlogicPgpKeyGenerationTypeECDH_initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_(self, curve);
  return self;
}

+ (LibComAfterlogicPgpKeyGenerationTypeECDH *)fromCurveWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve:(LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *)curve {
  return LibComAfterlogicPgpKeyGenerationTypeECDH_fromCurveWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_(curve);
}

- (NSString *)getName {
  return @"ECDH";
}

- (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)getAlgorithm {
  return JreLoadEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ECDH);
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)getAlgorithmSpec {
  return new_LibOrgBouncycastleJceSpecECNamedCurveGenParameterSpec_initWithNSString_([((LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *) nil_chk(curve_)) getName]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationTypeECDH;", 0x9, 1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve:);
  methods[1].selector = @selector(fromCurveWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve:);
  methods[2].selector = @selector(getName);
  methods[3].selector = @selector(getAlgorithm);
  methods[4].selector = @selector(getAlgorithmSpec);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "curve_", "LLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve;", "fromCurve" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationTypeECDH = { "ECDH", "lib.com.afterlogic.pgp.key.generation.type", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyGenerationTypeECDH;
}

@end

void LibComAfterlogicPgpKeyGenerationTypeECDH_initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_(LibComAfterlogicPgpKeyGenerationTypeECDH *self, LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *curve) {
  NSObject_init(self);
  self->curve_ = curve;
}

LibComAfterlogicPgpKeyGenerationTypeECDH *new_LibComAfterlogicPgpKeyGenerationTypeECDH_initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_(LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *curve) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationTypeECDH, initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_, curve)
}

LibComAfterlogicPgpKeyGenerationTypeECDH *create_LibComAfterlogicPgpKeyGenerationTypeECDH_initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_(LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *curve) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyGenerationTypeECDH, initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_, curve)
}

LibComAfterlogicPgpKeyGenerationTypeECDH *LibComAfterlogicPgpKeyGenerationTypeECDH_fromCurveWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_(LibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve *curve) {
  LibComAfterlogicPgpKeyGenerationTypeECDH_initialize();
  return new_LibComAfterlogicPgpKeyGenerationTypeECDH_initWithLibComAfterlogicPgpKeyGenerationTypeCurveEllipticCurve_(curve);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationTypeECDH)