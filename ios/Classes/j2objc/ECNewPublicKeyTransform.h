//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/ec/ECNewPublicKeyTransform.java
//

#ifndef ECNewPublicKeyTransform_H
#define ECNewPublicKeyTransform_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECPairTransform.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoEcECPair;
@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleMathEcECMultiplier;

@interface LibOrgBouncycastleCryptoEcECNewPublicKeyTransform : NSObject < LibOrgBouncycastleCryptoEcECPairTransform >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (LibOrgBouncycastleCryptoEcECPair *)transformWithLibOrgBouncycastleCryptoEcECPair:(LibOrgBouncycastleCryptoEcECPair *)cipherText;

#pragma mark Protected

- (id<LibOrgBouncycastleMathEcECMultiplier>)createBasePointMultiplier;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEcECNewPublicKeyTransform)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEcECNewPublicKeyTransform_init(LibOrgBouncycastleCryptoEcECNewPublicKeyTransform *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEcECNewPublicKeyTransform *new_LibOrgBouncycastleCryptoEcECNewPublicKeyTransform_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEcECNewPublicKeyTransform *create_LibOrgBouncycastleCryptoEcECNewPublicKeyTransform_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEcECNewPublicKeyTransform)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECNewPublicKeyTransform_H
