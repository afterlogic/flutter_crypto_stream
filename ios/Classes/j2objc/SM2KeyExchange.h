//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/SM2KeyExchange.java
//

#ifndef SM2KeyExchange_H
#define SM2KeyExchange_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoAgreementSM2KeyExchange : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (IOSByteArray *)calculateKeyWithInt:(jint)kLen
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)pubParam;

- (IOSObjectArray *)calculateKeyWithConfirmationWithInt:(jint)kLen
                                          withByteArray:(IOSByteArray *)confirmationTag
           withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)pubParam;

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)privParam OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoAgreementSM2KeyExchange)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementSM2KeyExchange_init(LibOrgBouncycastleCryptoAgreementSM2KeyExchange *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementSM2KeyExchange *new_LibOrgBouncycastleCryptoAgreementSM2KeyExchange_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementSM2KeyExchange *create_LibOrgBouncycastleCryptoAgreementSM2KeyExchange_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementSM2KeyExchange_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoAgreementSM2KeyExchange *self, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementSM2KeyExchange *new_LibOrgBouncycastleCryptoAgreementSM2KeyExchange_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementSM2KeyExchange *create_LibOrgBouncycastleCryptoAgreementSM2KeyExchange_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementSM2KeyExchange)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SM2KeyExchange_H
