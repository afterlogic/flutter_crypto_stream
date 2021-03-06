//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/RIPEMD256Digest.java
//

#ifndef RIPEMD256Digest_H
#define RIPEMD256Digest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GeneralDigest.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleUtilMemoable;

@interface LibOrgBouncycastleCryptoDigestsRIPEMD256Digest : LibOrgBouncycastleCryptoDigestsGeneralDigest

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigestsRIPEMD256Digest:(LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *)t;

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

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoDigestsRIPEMD256Digest)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsRIPEMD256Digest_init(LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *new_LibOrgBouncycastleCryptoDigestsRIPEMD256Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *create_LibOrgBouncycastleCryptoDigestsRIPEMD256Digest_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsRIPEMD256Digest_initWithLibOrgBouncycastleCryptoDigestsRIPEMD256Digest_(LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *self, LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *t);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *new_LibOrgBouncycastleCryptoDigestsRIPEMD256Digest_initWithLibOrgBouncycastleCryptoDigestsRIPEMD256Digest_(LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *t) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *create_LibOrgBouncycastleCryptoDigestsRIPEMD256Digest_initWithLibOrgBouncycastleCryptoDigestsRIPEMD256Digest_(LibOrgBouncycastleCryptoDigestsRIPEMD256Digest *t);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsRIPEMD256Digest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RIPEMD256Digest_H
