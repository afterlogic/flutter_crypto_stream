//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/gost/KeyFactorySpi.java
//

#ifndef KeyFactorySpi_H
#define KeyFactorySpi_H

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

@interface LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi : LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi_init(LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi *new_LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi *create_LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricGostKeyFactorySpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyFactorySpi_H
