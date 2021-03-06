//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/RIPEMD128Digest.java
//

#ifndef RIPEMD128Digest_H
#define RIPEMD128Digest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GeneralDigest.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleUtilMemoable;

@interface LibOrgBouncycastleCryptoDigestsRIPEMD128Digest : LibOrgBouncycastleCryptoDigestsGeneralDigest

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigestsRIPEMD128Digest:(LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *)t;

- (id<LibOrgBouncycastleUtilMemoable>)copy__ OBJC_METHOD_FAMILY_NONE;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getDigestSize;

- (void)reset;

- (void)resetWithLibOrgBouncycastleUtilMemoable:(id<LibOrgBouncycastleUtilMemoable>)other;

#pragma mark Protected

- (void)processBlock;

- (void)processLengthWithLong:(jlong)bitLength;

- (void)processWordWithByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inOff;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigestsGeneralDigest:(LibOrgBouncycastleCryptoDigestsGeneralDigest *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoDigestsRIPEMD128Digest)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsRIPEMD128Digest_init(LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *new_LibOrgBouncycastleCryptoDigestsRIPEMD128Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *create_LibOrgBouncycastleCryptoDigestsRIPEMD128Digest_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsRIPEMD128Digest_initWithLibOrgBouncycastleCryptoDigestsRIPEMD128Digest_(LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *self, LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *t);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *new_LibOrgBouncycastleCryptoDigestsRIPEMD128Digest_initWithLibOrgBouncycastleCryptoDigestsRIPEMD128Digest_(LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *t) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *create_LibOrgBouncycastleCryptoDigestsRIPEMD128Digest_initWithLibOrgBouncycastleCryptoDigestsRIPEMD128Digest_(LibOrgBouncycastleCryptoDigestsRIPEMD128Digest *t);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsRIPEMD128Digest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RIPEMD128Digest_H
