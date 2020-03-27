//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/CramerShoupKeyGenerationParameters.java
//

#ifndef CramerShoupKeyGenerationParameters_H
#define CramerShoupKeyGenerationParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KeyGenerationParameters.h"

@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsCramerShoupParameters;

@interface LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters : LibOrgBouncycastleCryptoKeyGenerationParameters

#pragma mark Public

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
   withLibOrgBouncycastleCryptoParamsCramerShoupParameters:(LibOrgBouncycastleCryptoParamsCramerShoupParameters *)params;

- (LibOrgBouncycastleCryptoParamsCramerShoupParameters *)getParameters;

#pragma mark Package-Private

+ (jint)getStrengthWithLibOrgBouncycastleCryptoParamsCramerShoupParameters:(LibOrgBouncycastleCryptoParamsCramerShoupParameters *)params;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)arg0
                                                   withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsCramerShoupParameters_(LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters *self, JavaSecuritySecureRandom *random, LibOrgBouncycastleCryptoParamsCramerShoupParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters *new_LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsCramerShoupParameters_(JavaSecuritySecureRandom *random, LibOrgBouncycastleCryptoParamsCramerShoupParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters *create_LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsCramerShoupParameters_(JavaSecuritySecureRandom *random, LibOrgBouncycastleCryptoParamsCramerShoupParameters *params);

FOUNDATION_EXPORT jint LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters_getStrengthWithLibOrgBouncycastleCryptoParamsCramerShoupParameters_(LibOrgBouncycastleCryptoParamsCramerShoupParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsCramerShoupKeyGenerationParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CramerShoupKeyGenerationParameters_H