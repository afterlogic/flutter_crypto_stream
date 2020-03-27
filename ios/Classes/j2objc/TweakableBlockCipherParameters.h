//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/TweakableBlockCipherParameters.java
//

#ifndef TweakableBlockCipherParameters_H
#define TweakableBlockCipherParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CipherParameters.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoParamsKeyParameter;

@interface LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters : NSObject < LibOrgBouncycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsKeyParameter:(LibOrgBouncycastleCryptoParamsKeyParameter *)key
                                                               withByteArray:(IOSByteArray *)tweak;

- (LibOrgBouncycastleCryptoParamsKeyParameter *)getKey;

- (IOSByteArray *)getTweak;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters_initWithLibOrgBouncycastleCryptoParamsKeyParameter_withByteArray_(LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters *self, LibOrgBouncycastleCryptoParamsKeyParameter *key, IOSByteArray *tweak);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters *new_LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters_initWithLibOrgBouncycastleCryptoParamsKeyParameter_withByteArray_(LibOrgBouncycastleCryptoParamsKeyParameter *key, IOSByteArray *tweak) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters *create_LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters_initWithLibOrgBouncycastleCryptoParamsKeyParameter_withByteArray_(LibOrgBouncycastleCryptoParamsKeyParameter *key, IOSByteArray *tweak);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsTweakableBlockCipherParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TweakableBlockCipherParameters_H