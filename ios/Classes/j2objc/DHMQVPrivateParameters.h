//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DHMQVPrivateParameters.java
//

#ifndef DHMQVPrivateParameters_H
#define DHMQVPrivateParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CipherParameters.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;
@class LibOrgBouncycastleCryptoParamsDHPublicKeyParameters;

@interface LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters : NSObject < LibOrgBouncycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)staticPrivateKey
                              withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)ephemeralPrivateKey;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)staticPrivateKey
                              withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)ephemeralPrivateKey
                               withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)ephemeralPublicKey;

- (LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)getEphemeralPrivateKey;

- (LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)getEphemeralPublicKey;

- (LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)getStaticPrivateKey;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *self, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *new_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *create_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *self, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *new_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *create_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DHMQVPrivateParameters_H
