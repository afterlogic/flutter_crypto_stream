//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/XDHUPrivateParameters.java
//

#ifndef XDHUPrivateParameters_H
#define XDHUPrivateParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CipherParameters.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;

@interface LibOrgBouncycastleCryptoParamsXDHUPrivateParameters : NSObject < LibOrgBouncycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)staticPrivateKey
                              withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)ephemeralPrivateKey;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)staticPrivateKey
                              withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)ephemeralPrivateKey
                              withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)ephemeralPublicKey;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getEphemeralPrivateKey;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getEphemeralPublicKey;

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getStaticPrivateKey;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsXDHUPrivateParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsXDHUPrivateParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsXDHUPrivateParameters *self, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPrivateKey);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsXDHUPrivateParameters *new_LibOrgBouncycastleCryptoParamsXDHUPrivateParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPrivateKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsXDHUPrivateParameters *create_LibOrgBouncycastleCryptoParamsXDHUPrivateParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPrivateKey);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsXDHUPrivateParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsXDHUPrivateParameters *self, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsXDHUPrivateParameters *new_LibOrgBouncycastleCryptoParamsXDHUPrivateParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsXDHUPrivateParameters *create_LibOrgBouncycastleCryptoParamsXDHUPrivateParameters_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *staticPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *ephemeralPublicKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsXDHUPrivateParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XDHUPrivateParameters_H
