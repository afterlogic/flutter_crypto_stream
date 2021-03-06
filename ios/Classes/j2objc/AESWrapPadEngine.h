//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/AESWrapPadEngine.java
//

#ifndef AESWrapPadEngine_H
#define AESWrapPadEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "RFC5649WrapEngine.h"

@protocol LibOrgBouncycastleCryptoBlockCipher;

@interface LibOrgBouncycastleCryptoEnginesAESWrapPadEngine : LibOrgBouncycastleCryptoEnginesRFC5649WrapEngine

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesAESWrapPadEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesAESWrapPadEngine_init(LibOrgBouncycastleCryptoEnginesAESWrapPadEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesAESWrapPadEngine *new_LibOrgBouncycastleCryptoEnginesAESWrapPadEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesAESWrapPadEngine *create_LibOrgBouncycastleCryptoEnginesAESWrapPadEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesAESWrapPadEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AESWrapPadEngine_H
