//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/ECKeyGenerationParameters.java
//

#include "ECDomainParameters.h"
#include "ECKeyGenerationParameters.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoParamsECKeyGenerationParameters () {
 @public
  LibOrgBouncycastleCryptoParamsECDomainParameters *domainParams_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsECKeyGenerationParameters, domainParams_, LibOrgBouncycastleCryptoParamsECDomainParameters *)

@implementation LibOrgBouncycastleCryptoParamsECKeyGenerationParameters

- (instancetype)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)domainParams
                                            withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(self, domainParams, random);
  return self;
}

- (LibOrgBouncycastleCryptoParamsECDomainParameters *)getDomainParameters {
  return domainParams_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsECDomainParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoParamsECDomainParameters:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(getDomainParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "domainParams_", "LLibOrgBouncycastleCryptoParamsECDomainParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsECDomainParameters;LJavaSecuritySecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsECKeyGenerationParameters = { "ECKeyGenerationParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters;
}

@end

void LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *self, LibOrgBouncycastleCryptoParamsECDomainParameters *domainParams, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(self, random, [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(domainParams)) getN])) bitLength]);
  self->domainParams_ = domainParams;
}

LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *new_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsECDomainParameters *domainParams, JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsECKeyGenerationParameters, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_, domainParams, random)
}

LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *create_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsECDomainParameters *domainParams, JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsECKeyGenerationParameters, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_, domainParams, random)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsECKeyGenerationParameters)