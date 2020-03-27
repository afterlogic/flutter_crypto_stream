//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/ECKeyGenerationParameters.java
//

#ifndef ECKeyGenerationParameters_H
#define ECKeyGenerationParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KeyGenerationParameters.h"

@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsECDomainParameters;

@interface LibOrgBouncycastleCryptoParamsECKeyGenerationParameters : LibOrgBouncycastleCryptoKeyGenerationParameters

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)domainParams
                                                      withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (LibOrgBouncycastleCryptoParamsECDomainParameters *)getDomainParameters;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)arg0
                                                   withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsECKeyGenerationParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *self, LibOrgBouncycastleCryptoParamsECDomainParameters *domainParams, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *new_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsECDomainParameters *domainParams, JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *create_LibOrgBouncycastleCryptoParamsECKeyGenerationParameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsECDomainParameters *domainParams, JavaSecuritySecureRandom *random);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsECKeyGenerationParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECKeyGenerationParameters_H