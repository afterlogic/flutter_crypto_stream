//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/rsa/JcajceRsaKeyFactorySpi.java
//

#ifndef JcajceRsaKeyFactorySpi_H
#define JcajceRsaKeyFactorySpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BaseKeyFactorySpi.h"
#include "J2ObjC_header.h"

@class IOSClass;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@protocol JavaSecurityKey;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecKeySpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi : LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo;

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo;

#pragma mark Protected

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)spec;

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyFactorySpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceRsaKeyFactorySpi_H