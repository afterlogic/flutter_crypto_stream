//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DHKeyParameters.java
//

#include "AsymmetricKeyParameter.h"
#include "DHKeyParameters.h"
#include "DHParameters.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoParamsDHKeyParameters () {
 @public
  LibOrgBouncycastleCryptoParamsDHParameters *params_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHKeyParameters, params_, LibOrgBouncycastleCryptoParamsDHParameters *)

@implementation LibOrgBouncycastleCryptoParamsDHKeyParameters

- (instancetype)initWithBoolean:(jboolean)isPrivate
withLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)params {
  LibOrgBouncycastleCryptoParamsDHKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsDHParameters_(self, isPrivate, params);
  return self;
}

- (LibOrgBouncycastleCryptoParamsDHParameters *)getParameters {
  return params_;
}

- (jboolean)isEqual:(id)obj {
  if (!([obj isKindOfClass:[LibOrgBouncycastleCryptoParamsDHKeyParameters class]])) {
    return false;
  }
  LibOrgBouncycastleCryptoParamsDHKeyParameters *dhKey = (LibOrgBouncycastleCryptoParamsDHKeyParameters *) cast_chk(obj, [LibOrgBouncycastleCryptoParamsDHKeyParameters class]);
  if (params_ == nil) {
    return [((LibOrgBouncycastleCryptoParamsDHKeyParameters *) nil_chk(dhKey)) getParameters] == nil;
  }
  else {
    return [params_ isEqual:[((LibOrgBouncycastleCryptoParamsDHKeyParameters *) nil_chk(dhKey)) getParameters]];
  }
}

- (NSUInteger)hash {
  jint code = [self isPrivate] ? 0 : 1;
  if (params_ != nil) {
    code ^= ((jint) [params_ hash]);
  }
  return code;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withLibOrgBouncycastleCryptoParamsDHParameters:);
  methods[1].selector = @selector(getParameters);
  methods[2].selector = @selector(isEqual:);
  methods[3].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastleCryptoParamsDHParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZLLibOrgBouncycastleCryptoParamsDHParameters;", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsDHKeyParameters = { "DHKeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsDHKeyParameters;
}

@end

void LibOrgBouncycastleCryptoParamsDHKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHKeyParameters *self, jboolean isPrivate, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, isPrivate);
  self->params_ = params;
}

LibOrgBouncycastleCryptoParamsDHKeyParameters *new_LibOrgBouncycastleCryptoParamsDHKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsDHParameters_(jboolean isPrivate, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDHKeyParameters, initWithBoolean_withLibOrgBouncycastleCryptoParamsDHParameters_, isPrivate, params)
}

LibOrgBouncycastleCryptoParamsDHKeyParameters *create_LibOrgBouncycastleCryptoParamsDHKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsDHParameters_(jboolean isPrivate, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDHKeyParameters, initWithBoolean_withLibOrgBouncycastleCryptoParamsDHParameters_, isPrivate, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsDHKeyParameters)
