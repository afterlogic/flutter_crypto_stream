//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/CryptoProWrapEngine.java
//

#ifndef CryptoProWrapEngine_H
#define CryptoProWrapEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GOST28147WrapEngine.h"
#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine : LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine

#pragma mark Public

- (instancetype __nonnull)init;

- (void)init__WithBoolean:(jboolean)forWrapping
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine_init(LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine *new_LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine *create_LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesCryptoProWrapEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CryptoProWrapEngine_H
