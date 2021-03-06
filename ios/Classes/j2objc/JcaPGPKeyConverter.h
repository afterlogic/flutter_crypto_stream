//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaPGPKeyConverter.java
//

#ifndef JcaPGPKeyConverter_H
#define JcaPGPKeyConverter_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecurityProvider;
@class JavaUtilDate;
@class LibOrgBouncycastleOpenpgpPGPPrivateKey;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol LibOrgBouncycastleOpenpgpPGPAlgorithmParameters;

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleOpenpgpPGPPrivateKey *)getPGPPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pub
                                                                           withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privKey;

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPGPPublicKeyWithInt:(jint)algorithm
              withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:(id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters>)algorithmParameters
                                        withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)pubKey
                                                 withJavaUtilDate:(JavaUtilDate *)time;

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPGPPublicKeyWithInt:(jint)algorithm
                                        withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)pubKey
                                                 withJavaUtilDate:(JavaUtilDate *)time;

- (id<JavaSecurityPrivateKey>)getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)privKey;

- (id<JavaSecurityPublicKey>)getPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)publicKey;

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter *)setProviderWithJavaSecurityProvider:(JavaSecurityProvider *)provider;

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter *)setProviderWithNSString:(NSString *)providerName;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter_init(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter *self);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaPGPKeyConverter_H
