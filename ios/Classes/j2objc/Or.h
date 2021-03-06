//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/key/util/Or.java
//

#ifndef Or_H
#define Or_H

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

@interface LibComAfterlogicPgpKeySelectionKeyUtilOr : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyUtilOr)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyUtilOr_init(LibComAfterlogicPgpKeySelectionKeyUtilOr *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyUtilOr *new_LibComAfterlogicPgpKeySelectionKeyUtilOr_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyUtilOr *create_LibComAfterlogicPgpKeySelectionKeyUtilOr_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyUtilOr)

@interface LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy : LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy

#pragma mark Public

- (instancetype __nonnull)initWithLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy:(LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *)left
                              withLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy:(LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *)right;

- (jboolean)acceptWithId:(id)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy_initWithLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_withLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_(LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy *self, LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *left, LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *right);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy_initWithLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_withLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_(LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *left, LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *right) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy_initWithLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_withLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_(LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *left, LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *right);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyUtilOr_PubKeySelectionStrategy)

@interface LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy : LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy

#pragma mark Public

- (instancetype __nonnull)initWithLibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy:(LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *)left
                              withLibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy:(LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *)right;

- (jboolean)acceptWithId:(id)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPSecretKey *)key;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy_initWithLibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy_withLibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy_(LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy *self, LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *left, LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *right);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy_initWithLibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy_withLibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy_(LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *left, LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *right) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy_initWithLibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy_withLibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy_(LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *left, LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *right);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyUtilOr_SecKeySelectionStrategy)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Or_H
