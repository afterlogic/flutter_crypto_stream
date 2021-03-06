//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/ShortenedDigest.java
//

#ifndef ShortenedDigest_H
#define ShortenedDigest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExtendedDigest.h"
#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoDigestsShortenedDigest : NSObject < LibOrgBouncycastleCryptoExtendedDigest >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoExtendedDigest:(id<LibOrgBouncycastleCryptoExtendedDigest>)baseDigest
                                                                 withInt:(jint)length;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getByteLength;

- (jint)getDigestSize;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoDigestsShortenedDigest)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsShortenedDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_(LibOrgBouncycastleCryptoDigestsShortenedDigest *self, id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest, jint length);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsShortenedDigest *new_LibOrgBouncycastleCryptoDigestsShortenedDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_(id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest, jint length) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsShortenedDigest *create_LibOrgBouncycastleCryptoDigestsShortenedDigest_initWithLibOrgBouncycastleCryptoExtendedDigest_withInt_(id<LibOrgBouncycastleCryptoExtendedDigest> baseDigest, jint length);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsShortenedDigest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ShortenedDigest_H
