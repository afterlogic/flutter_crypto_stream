//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DHKeyGenerationParameters.java
//

#include "DHKeyGenerationParameters.h"
#include "DHParameters.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters () {
 @public
  LibOrgBouncycastleCryptoParamsDHParameters *params_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters, params_, LibOrgBouncycastleCryptoParamsDHParameters *)

@implementation LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
  withLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)params {
  LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_(self, random, params);
  return self;
}

- (LibOrgBouncycastleCryptoParamsDHParameters *)getParameters {
  return params_;
}

+ (jint)getStrengthWithLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)params {
  return LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_getStrengthWithLibOrgBouncycastleCryptoParamsDHParameters_(params);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x8, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:withLibOrgBouncycastleCryptoParamsDHParameters:);
  methods[1].selector = @selector(getParameters);
  methods[2].selector = @selector(getStrengthWithLibOrgBouncycastleCryptoParamsDHParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastleCryptoParamsDHParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;LLibOrgBouncycastleCryptoParamsDHParameters;", "getStrength", "LLibOrgBouncycastleCryptoParamsDHParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters = { "DHKeyGenerationParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters;
}

@end

void LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *self, JavaSecuritySecureRandom *random, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(self, random, LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_getStrengthWithLibOrgBouncycastleCryptoParamsDHParameters_(params));
  self->params_ = params;
}

LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *new_LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_(JavaSecuritySecureRandom *random, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters, initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_, random, params)
}

LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *create_LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_(JavaSecuritySecureRandom *random, LibOrgBouncycastleCryptoParamsDHParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters, initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_, random, params)
}

jint LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_getStrengthWithLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHParameters *params) {
  LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_initialize();
  return [((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(params)) getL] != 0 ? [params getL] : [((JavaMathBigInteger *) nil_chk([params getP])) bitLength];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters)
