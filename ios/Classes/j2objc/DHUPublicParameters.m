//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DHUPublicParameters.java
//

#include "DHParameters.h"
#include "DHPublicKeyParameters.h"
#include "DHUPublicParameters.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"

@interface LibOrgBouncycastleCryptoParamsDHUPublicParameters () {
 @public
  LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *staticPublicKey_;
  LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHUPublicParameters, staticPublicKey_, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHUPublicParameters, ephemeralPublicKey_, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)

@implementation LibOrgBouncycastleCryptoParamsDHUPublicParameters

- (instancetype)initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)staticPublicKey
                    withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)ephemeralPublicKey {
  LibOrgBouncycastleCryptoParamsDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(self, staticPublicKey, ephemeralPublicKey);
  return self;
}

- (LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)getStaticPublicKey {
  return staticPublicKey_;
}

- (LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)getEphemeralPublicKey {
  return ephemeralPublicKey_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:);
  methods[1].selector = @selector(getStaticPublicKey);
  methods[2].selector = @selector(getEphemeralPublicKey);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "staticPublicKey_", "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ephemeralPublicKey_", "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsDHUPublicParameters = { "DHUPublicParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsDHUPublicParameters;
}

@end

void LibOrgBouncycastleCryptoParamsDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHUPublicParameters *self, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *staticPublicKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey) {
  NSObject_init(self);
  if (staticPublicKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"staticPublicKey cannot be null");
  }
  if (ephemeralPublicKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"ephemeralPublicKey cannot be null");
  }
  if (![((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk([staticPublicKey getParameters])) isEqual:[ephemeralPublicKey getParameters]]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Static and ephemeral public keys have different domain parameters");
  }
  self->staticPublicKey_ = staticPublicKey;
  self->ephemeralPublicKey_ = ephemeralPublicKey;
}

LibOrgBouncycastleCryptoParamsDHUPublicParameters *new_LibOrgBouncycastleCryptoParamsDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *staticPublicKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDHUPublicParameters, initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_, staticPublicKey, ephemeralPublicKey)
}

LibOrgBouncycastleCryptoParamsDHUPublicParameters *create_LibOrgBouncycastleCryptoParamsDHUPublicParameters_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *staticPublicKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDHUPublicParameters, initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_, staticPublicKey, ephemeralPublicKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsDHUPublicParameters)