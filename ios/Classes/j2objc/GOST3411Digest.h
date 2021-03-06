//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/GOST3411Digest.java
//

#ifndef GOST3411Digest_H
#define GOST3411Digest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExtendedDigest.h"
#include "J2ObjC_header.h"
#include "Memoable.h"

@class IOSByteArray;
@class IOSShortArray;

@interface LibOrgBouncycastleCryptoDigestsGOST3411Digest : NSObject < LibOrgBouncycastleCryptoExtendedDigest, LibOrgBouncycastleUtilMemoable > {
 @public
  IOSByteArray *a_;
  IOSShortArray *wS_;
  IOSShortArray *w_S_;
  IOSByteArray *S_;
  IOSByteArray *U_;
  IOSByteArray *V_;
  IOSByteArray *W_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)sBoxParam;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest:(LibOrgBouncycastleCryptoDigestsGOST3411Digest *)t;

- (id<LibOrgBouncycastleUtilMemoable>)copy__ OBJC_METHOD_FAMILY_NONE;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getByteLength;

- (jint)getDigestSize;

- (void)reset;

- (void)resetWithLibOrgBouncycastleUtilMemoable:(id<LibOrgBouncycastleUtilMemoable>)other;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

#pragma mark Protected

- (void)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoDigestsGOST3411Digest)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, a_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, wS_, IOSShortArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, w_S_, IOSShortArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, S_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, U_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, V_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, W_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsGOST3411Digest_init(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsGOST3411Digest *new_LibOrgBouncycastleCryptoDigestsGOST3411Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsGOST3411Digest *create_LibOrgBouncycastleCryptoDigestsGOST3411Digest_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *sBoxParam);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsGOST3411Digest *new_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithByteArray_(IOSByteArray *sBoxParam) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsGOST3411Digest *create_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithByteArray_(IOSByteArray *sBoxParam);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, LibOrgBouncycastleCryptoDigestsGOST3411Digest *t);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsGOST3411Digest *new_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *t) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDigestsGOST3411Digest *create_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *t);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDigestsGOST3411Digest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3411Digest_H
