//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/collection/PGPKeyRingUtil.java
//

#ifndef PGPKeyRingUtil_H
#define PGPKeyRingUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibComAfterlogicPgpKeyOpenPgpV4Fingerprint;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@class LibOrgBouncycastleOpenpgpPGPPublicKeyRing;
@class LibOrgBouncycastleOpenpgpPGPSecretKeyRing;

@interface LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeys;

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeys
                              withLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeys;

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeys;

- (jlong)getKeyId;

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getMasterKey;

- (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)getPublicKeys;

- (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)getSecretKeys;

- (LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *)getV4Fingerprint;

- (jboolean)hasSecretKeys;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *self, LibOrgBouncycastleOpenpgpPGPPublicKeyRing *publicKeys, LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *new_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *publicKeys, LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *create_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *publicKeys, LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys);

FOUNDATION_EXPORT void LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *self, LibOrgBouncycastleOpenpgpPGPPublicKeyRing *publicKeys);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *new_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *publicKeys) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *create_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *publicKeys);

FOUNDATION_EXPORT void LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *self, LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *new_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *create_LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPKeyRingUtil_H
