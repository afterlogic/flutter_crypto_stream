//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/ARIAWrapEngine.java
//

#ifndef ARIAWrapEngine_H
#define ARIAWrapEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "RFC3394WrapEngine.h"

@protocol LibOrgBouncycastleCryptoBlockCipher;

@interface LibOrgBouncycastleCryptoEnginesARIAWrapEngine : LibOrgBouncycastleCryptoEnginesRFC3394WrapEngine

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithBoolean:(jboolean)useReverseDirection;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesARIAWrapEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesARIAWrapEngine_init(LibOrgBouncycastleCryptoEnginesARIAWrapEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesARIAWrapEngine *new_LibOrgBouncycastleCryptoEnginesARIAWrapEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesARIAWrapEngine *create_LibOrgBouncycastleCryptoEnginesARIAWrapEngine_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesARIAWrapEngine_initWithBoolean_(LibOrgBouncycastleCryptoEnginesARIAWrapEngine *self, jboolean useReverseDirection);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesARIAWrapEngine *new_LibOrgBouncycastleCryptoEnginesARIAWrapEngine_initWithBoolean_(jboolean useReverseDirection) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesARIAWrapEngine *create_LibOrgBouncycastleCryptoEnginesARIAWrapEngine_initWithBoolean_(jboolean useReverseDirection);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesARIAWrapEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ARIAWrapEngine_H
