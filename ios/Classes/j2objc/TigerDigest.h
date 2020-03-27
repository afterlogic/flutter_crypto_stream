//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/TigerDigest.java
//

#ifndef TigerDigest_H
#define TigerDigest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExtendedDigest.h"
#include "J2ObjC_header.h"
#include "Memoable.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoDigestsTigerDigest : NSObject < LibOrgBouncycastleCryptoExtendedDigest, LibOrgBouncycastleUtilMemoable >

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigestsTigerDigest:(LibOrgBouncycastleCryptoDigestsTigerDigest *)t;

- (id<LibOrgBouncycastleUtilMemoable>)copy__ OBJC_METHOD_FAMILY_NONE;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getByteLength;

- (jint)getDigestSize;

- (void)reset;

- (void)resetWithLibOrgBouncycastleUtilMemoable:(id<LibOrgBouncycastleUtilMemoable>)other;

- (void)unpackWordWithLong:(jlong)r
             withByteArray:(IOSByteArray *)outArg
                   withInt:(jint)outOff;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoDigestsTigerDigest)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsTigerDigest_init(LibOrgBouncycastleCryptoDigestsTigerDigest *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsTigerDigest *new_LibOrgBouncycastleCryptoDigestsTigerDigest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsTigerDigest *create_LibOrgBouncycastleCryptoDigestsTigerDigest_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsTigerDigest_initWithLibOrgBouncycastleCryptoDigestsTigerDigest_(LibOrgBouncycastleCryptoDigestsTigerDigest *self, LibOrgBouncycastleCryptoDigestsTigerDigest *t);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsTigerDigest *new_LibOrgBouncycastleCryptoDigestsTigerDigest_initWithLibOrgBouncycastleCryptoDigestsTigerDigest_(LibOrgBouncycastleCryptoDigestsTigerDigest *t) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsTigerDigest *create_LibOrgBouncycastleCryptoDigestsTigerDigest_initWithLibOrgBouncycastleCryptoDigestsTigerDigest_(LibOrgBouncycastleCryptoDigestsTigerDigest *t);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsTigerDigest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TigerDigest_H