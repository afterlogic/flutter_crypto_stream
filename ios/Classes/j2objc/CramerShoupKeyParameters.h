//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/CramerShoupKeyParameters.java
//

#ifndef CramerShoupKeyParameters_H
#define CramerShoupKeyParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyParameter.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoParamsCramerShoupParameters;

@interface LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters : LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter

#pragma mark Public

- (jboolean)isEqual:(id)obj;

- (LibOrgBouncycastleCryptoParamsCramerShoupParameters *)getParameters;

- (NSUInteger)hash;

#pragma mark Protected

- (instancetype __nonnull)initWithBoolean:(jboolean)isPrivate
withLibOrgBouncycastleCryptoParamsCramerShoupParameters:(LibOrgBouncycastleCryptoParamsCramerShoupParameters *)params;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsCramerShoupParameters_(LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *self, jboolean isPrivate, LibOrgBouncycastleCryptoParamsCramerShoupParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *new_LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsCramerShoupParameters_(jboolean isPrivate, LibOrgBouncycastleCryptoParamsCramerShoupParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters *create_LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsCramerShoupParameters_(jboolean isPrivate, LibOrgBouncycastleCryptoParamsCramerShoupParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsCramerShoupKeyParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CramerShoupKeyParameters_H
