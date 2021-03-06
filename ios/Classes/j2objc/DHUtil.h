//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/DHUtil.java
//

#ifndef DHUtil_H
#define DHUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;

@interface LibOrgBouncycastleJceProviderDHUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePrivateKeyParameterWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key;

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderDHUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderDHUtil_init(LibOrgBouncycastleJceProviderDHUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderDHUtil *new_LibOrgBouncycastleJceProviderDHUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderDHUtil *create_LibOrgBouncycastleJceProviderDHUtil_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJceProviderDHUtil_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJceProviderDHUtil_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> key);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderDHUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DHUtil_H
