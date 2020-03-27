//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/DSTU7624WrapEngine.java
//

#ifndef DSTU7624WrapEngine_H
#define DSTU7624WrapEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Wrapper.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine : NSObject < LibOrgBouncycastleCryptoWrapper >

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)blockBitLength;

- (NSString *)getAlgorithmName;

- (void)init__WithBoolean:(jboolean)forWrapping
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)inArg
                              withInt:(jint)inOff
                              withInt:(jint)inLen;

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                            withInt:(jint)inLen;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine_initWithInt_(LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine *self, jint blockBitLength);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine *new_LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine_initWithInt_(jint blockBitLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine *create_LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine_initWithInt_(jint blockBitLength);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesDSTU7624WrapEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSTU7624WrapEngine_H