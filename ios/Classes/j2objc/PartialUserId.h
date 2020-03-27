//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/keyring/impl/PartialUserId.java
//

#ifndef PartialUserId_H
#define PartialUserId_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PublicKeySelectionStrategy.h"
#include "SecretKeySelectionStrategy.h"

@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@class LibOrgBouncycastleOpenpgpPGPSecretKey;

@interface LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_init(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId *new_LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId *create_LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId)

@interface LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy : LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)acceptWithId:(NSString *)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_PubRingSelectionStrategy)

@interface LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy : LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)acceptWithId:(NSString *)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPSecretKey *)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyringImplPartialUserId_SecRingSelectionStrategy)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PartialUserId_H