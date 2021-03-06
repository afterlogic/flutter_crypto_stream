//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/ECPublicKeyParameters.java
//

#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECKeyParameters.h"
#include "ECPoint.h"
#include "ECPublicKeyParameters.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoParamsECPublicKeyParameters () {
 @public
  LibOrgBouncycastleMathEcECPoint *Q_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsECPublicKeyParameters, Q_, LibOrgBouncycastleMathEcECPoint *)

@implementation LibOrgBouncycastleCryptoParamsECPublicKeyParameters

- (instancetype)initWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)Q
   withLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)params {
  LibOrgBouncycastleCryptoParamsECPublicKeyParameters_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleCryptoParamsECDomainParameters_(self, Q, params);
  return self;
}

- (LibOrgBouncycastleMathEcECPoint *)getQ {
  return Q_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcECPoint:withLibOrgBouncycastleCryptoParamsECDomainParameters:);
  methods[1].selector = @selector(getQ);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "Q_", "LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleMathEcECPoint;LLibOrgBouncycastleCryptoParamsECDomainParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsECPublicKeyParameters = { "ECPublicKeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsECPublicKeyParameters;
}

@end

void LibOrgBouncycastleCryptoParamsECPublicKeyParameters_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleCryptoParamsECPublicKeyParameters *self, LibOrgBouncycastleMathEcECPoint *Q, LibOrgBouncycastleCryptoParamsECDomainParameters *params) {
  LibOrgBouncycastleCryptoParamsECKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsECDomainParameters_(self, false, params);
  self->Q_ = LibOrgBouncycastleCryptoParamsECDomainParameters_validateWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_([((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(params)) getCurve], Q);
}

LibOrgBouncycastleCryptoParamsECPublicKeyParameters *new_LibOrgBouncycastleCryptoParamsECPublicKeyParameters_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleMathEcECPoint *Q, LibOrgBouncycastleCryptoParamsECDomainParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsECPublicKeyParameters, initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleCryptoParamsECDomainParameters_, Q, params)
}

LibOrgBouncycastleCryptoParamsECPublicKeyParameters *create_LibOrgBouncycastleCryptoParamsECPublicKeyParameters_initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleMathEcECPoint *Q, LibOrgBouncycastleCryptoParamsECDomainParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsECPublicKeyParameters, initWithLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleCryptoParamsECDomainParameters_, Q, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsECPublicKeyParameters)
