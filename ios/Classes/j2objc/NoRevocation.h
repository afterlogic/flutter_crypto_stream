//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/key/impl/NoRevocation.java
//

#ifndef NoRevocation_H
#define NoRevocation_H

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

@interface LibComAfterlogicPgpKeySelectionKeyImplNoRevocation : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_init(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyImplNoRevocation *new_LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyImplNoRevocation *create_LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation)

@interface LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy : LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)acceptWithId:(id)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy)

@interface LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy : LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy

#pragma mark Public

- (instancetype __nonnull)init;

- (jboolean)acceptWithId:(id)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPSecretKey *)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy *self);

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_SecKeySelectionStrategy)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NoRevocation_H
